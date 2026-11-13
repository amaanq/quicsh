//! Single-threaded QUIC event loop over `quinn-proto`.
//!
//! - One [`Endpoint`] serves every socket, so a datagram is handled the same
//!   whichever socket the kernel delivered it to.
//! - Each connection owns a UDP socket connected to its peer. The kernel then
//!   gives it a receive queue of its own, and one connection's bulk data cannot
//!   delay another connection's packets.
//! - A server also keeps an unconnected listener on the same port, which
//!   receives first packets and packets from peers that changed address.

use std::{
   collections::HashMap,
   io::{
      self,
      IoSliceMut,
   },
   net::{
      IpAddr,
      Ipv4Addr,
      Ipv6Addr,
      SocketAddr,
      UdpSocket,
   },
   str::FromStr,
   sync::Arc,
   time::Instant,
};

use bytes::BytesMut;
use quinn_proto::{
   ClientConfig,
   Connection,
   ConnectionHandle,
   DatagramEvent,
   EcnCodepoint,
   Endpoint,
   EndpointConfig,
   Event,
   Incoming,
   MtuDiscoveryConfig,
   ServerConfig,
   Transmit,
   TransportConfig,
   VarInt,
   congestion::{
      BbrConfig,
      CubicConfig,
   },
   crypto::rustls::{
      QuicClientConfig,
      QuicServerConfig,
   },
};
use quinn_udp::{
   BATCH_SIZE,
   RecvMeta,
   UdpSocketState,
   is_msg_size_err,
};
use rustix::{
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   net::{
      AddressFamily,
      SocketFlags,
      SocketType,
      bind,
      connect,
      socket_with,
      sockopt::{
         ip_mtu,
         ipv6_mtu,
         set_socket_reuseport,
      },
   },
   time::Timespec,
};

use crate::error::Error;

/// Send window floor for a connection that carries keystrokes.
pub const INTERACTIVE_WINDOW: u64 = 256 << 10;
/// Send window floor for a connection that carries only bulk data.
pub const BULK_WINDOW: u64 = 1 << 20;

const RECV_LEN: usize = 1 << 16;
const SOCKET_BUFFER: usize = 4 << 20;
const RECV_ROUNDS: usize = 8;
const SEND_ROUNDS: usize = 64;
const SEND_WINDOW_CEILING: u64 = 64 << 20;
const RATE_CEILING: f64 = 10.0e9 / 8.0;
const MIN_UDP_PAYLOAD: u16 = 1200;
const MAX_UDP_PAYLOAD: u16 = 65527;
const MAX_UDP_PAYLOAD_V4: u16 = 65507;
const IDLE_TIMEOUT_MS: u32 = 10_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
   #[default]
   Bbr,
   Cubic,
}

impl FromStr for Congestion {
   type Err = Error;

   fn from_str(name: &str) -> Result<Self, Error> {
      match name {
         "bbr" => Ok(Self::Bbr),
         "cubic" => Ok(Self::Cubic),
         other => Err(Error::Congestion(other.to_owned())),
      }
   }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Tuning {
   pub congestion: Congestion,
   /// Largest UDP payload MTU discovery may try. `None` takes it from the
   /// route to the peer.
   pub mtu_bound:  Option<u16>,
}

impl Tuning {
   fn transport(self, route_bound: u16) -> Arc<TransportConfig> {
      let mut discovery = MtuDiscoveryConfig::default();
      discovery.upper_bound(self.mtu_bound.unwrap_or(route_bound));

      let mut transport = TransportConfig::default();

      transport
         .stream_receive_window(VarInt::from_u32(16 << 20))
         .receive_window(VarInt::from_u32(64 << 20))
         .send_window(INTERACTIVE_WINDOW)
         .max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
         .mtu_discovery_config(Some(discovery));

      match self.congestion {
         Congestion::Bbr => transport.congestion_controller_factory(Arc::new(BbrConfig::default())),
         Congestion::Cubic => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()))
         },
      };

      Arc::new(transport)
   }
}

pub trait App {
   type Error: From<Error>;

   /// # Errors
   ///
   /// An error stops [`Transport::run`].
   fn event(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
      event: Event,
   ) -> Result<(), Self::Error>;

   /// Runs once per loop iteration for every connection and returns the next
   /// instant the app wants to run at.
   ///
   /// # Errors
   ///
   /// An error stops [`Transport::run`].
   fn tick(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>, Self::Error>;

   fn done(&self) -> bool;
}

struct Socket {
   io:    UdpSocket,
   state: UdpSocketState,
}

impl Socket {
   fn open(local: SocketAddr, remote: Option<SocketAddr>) -> Result<Self, Error> {
      let family = if local.is_ipv4() {
         AddressFamily::INET
      } else {
         AddressFamily::INET6
      };

      let setup = || {
         let fd = socket_with(family, SocketType::DGRAM, SocketFlags::CLOEXEC, None)?;
         set_socket_reuseport(&fd, true)?;
         bind(&fd, &local)?;

         if let Some(remote) = remote {
            connect(&fd, &remote)?;
         }

         let io = UdpSocket::from(fd);
         let state = UdpSocketState::new((&io).into())?;
         state.set_send_buffer_size((&io).into(), SOCKET_BUFFER)?;
         state.set_recv_buffer_size((&io).into(), SOCKET_BUFFER)?;

         io::Result::Ok(Self { io, state })
      };

      setup().map_err(Error::Socket)
   }

   /// Largest UDP payload that fits the route this connected socket uses.
   fn payload_bound(&self, remote: SocketAddr) -> Result<u16, Error> {
      let (mtu, overhead, ceiling) = if remote.is_ipv4() {
         (ip_mtu(&self.io), 28, MAX_UDP_PAYLOAD_V4)
      } else {
         (ipv6_mtu(&self.io), 48, MAX_UDP_PAYLOAD)
      };

      let payload = mtu
         .map_err(|errno| Error::Socket(errno.into()))?
         .saturating_sub(overhead);

      Ok(u16::try_from(payload).map_or(ceiling, |payload| payload.clamp(MIN_UDP_PAYLOAD, ceiling)))
   }

   /// Returns the number of filled buffers, or `None` when the socket has
   /// nothing queued.
   fn receive(
      &self,
      buffer: &mut [u8],
      metas: &mut [RecvMeta; BATCH_SIZE],
   ) -> Result<Option<usize>, Error> {
      let mut slices: Vec<_> = buffer.chunks_mut(RECV_LEN).map(IoSliceMut::new).collect();

      match self.state.recv((&self.io).into(), &mut slices, metas) {
         Ok(count) => Ok(Some(count)),
         // A peer whose port closed answers with ICMP, which a connected socket
         // reports once as ECONNREFUSED. The idle timeout ends that connection.
         Err(error)
            if matches!(
               error.kind(),
               io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionRefused
            ) =>
         {
            Ok(None)
         },
         Err(error) => Err(Error::Receive(error)),
      }
   }

   fn transmit(&self, meta: &Transmit, contents: &[u8]) -> Result<(), Error> {
      let datagrams = quinn_udp::Transmit {
         destination:  meta.destination,
         ecn:          meta
            .ecn
            .and_then(|codepoint| quinn_udp::EcnCodepoint::from_bits(codepoint as u8)),
         contents:     &contents[..meta.size],
         segment_size: meta.segment_size,
         src_ip:       meta.src_ip,
      };

      loop {
         match self.state.try_send((&self.io).into(), &datagrams) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
               poll(&mut [PollFd::new(&self.io, PollFlags::OUT)], None)
                  .map_err(|errno| Error::Poll(errno.into()))?;
            },
            // An MTU probe larger than the path fails with EMSGSIZE, and a
            // closed peer port with ECONNREFUSED. Loss detection handles both.
            Err(error)
               if is_msg_size_err(&error) || error.kind() == io::ErrorKind::ConnectionRefused =>
            {
               return Ok(());
            },
            Err(error) => return Err(Error::Send(error)),
         }
      }
   }
}

struct Session {
   connection:   Connection,
   socket:       Socket,
   window_floor: u64,
}

impl Session {
   /// Returns whether the connection still has packets to send.
   fn flush(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      endpoint: &mut Endpoint,
      buffer: &mut Vec<u8>,
   ) -> Result<bool, Error> {
      for _ in 0..SEND_ROUNDS {
         while let Some(event) = self.connection.poll_endpoint_events() {
            if let Some(reply) = endpoint.handle_event(handle, event) {
               self.connection.handle_event(reply);
            }
         }

         // The kernel rejects a GSO send whose segments total more than one UDP
         // payload.
         let mtu = usize::from(self.connection.current_mtu());
         let segments =
            (usize::from(MAX_UDP_PAYLOAD_V4) / mtu).clamp(1, self.socket.state.max_gso_segments());

         buffer.clear();
         let Some(meta) = self.connection.poll_transmit(now, segments, buffer) else {
            return Ok(false);
         };

         self.socket.transmit(&meta, buffer)?;
      }

      Ok(true)
   }
}

struct Listener {
   socket: Socket,
   local:  SocketAddr,
   config: ServerConfig,
}

#[derive(Clone, Copy)]
enum Source {
   Listener,
   Session(ConnectionHandle),
}

pub struct Transport {
   endpoint: Endpoint,
   listener: Option<Listener>,
   sessions: HashMap<ConnectionHandle, Session>,
   tuning:   Tuning,
   recv:     Vec<u8>,
   send:     Vec<u8>,
}

impl Transport {
   /// A transport that only makes outgoing connections.
   ///
   /// # Errors
   ///
   /// Fails when the endpoint rejects its configuration.
   pub fn new(tuning: Tuning) -> Result<Self, Error> {
      Self::build(None, tuning)
   }

   /// A transport that also accepts connections on `local`.
   ///
   /// # Errors
   ///
   /// Fails when the listening socket cannot be opened.
   pub fn listen(
      local: SocketAddr,
      crypto: Arc<QuicServerConfig>,
      tuning: Tuning,
   ) -> Result<Self, Error> {
      let listener = Listener {
         socket: Socket::open(local, None)?,
         local,
         config: ServerConfig::with_crypto(crypto),
      };

      Self::build(Some(listener), tuning)
   }

   fn build(listener: Option<Listener>, tuning: Tuning) -> Result<Self, Error> {
      let mut config = EndpointConfig::default();
      config
         .max_udp_payload_size(MAX_UDP_PAYLOAD)
         .map_err(Error::Config)?;

      let server = listener
         .as_ref()
         .map(|listener| Arc::new(listener.config.clone()));

      Ok(Self {
         endpoint: Endpoint::new(Arc::new(config), server, true, None),
         listener,
         sessions: HashMap::new(),
         tuning,
         recv: vec![0; RECV_LEN * BATCH_SIZE],
         send: Vec::with_capacity(RECV_LEN),
      })
   }

   /// Starts a connection to `remote` on a socket of its own.
   ///
   /// # Errors
   ///
   /// Fails when the socket cannot be opened or the endpoint refuses the
   /// connection attempt.
   pub fn connect(
      &mut self,
      now: Instant,
      remote: SocketAddr,
      server_name: &str,
      crypto: Arc<QuicClientConfig>,
      window_floor: u64,
   ) -> Result<ConnectionHandle, Error> {
      let unspecified: IpAddr = if remote.is_ipv4() {
         Ipv4Addr::UNSPECIFIED.into()
      } else {
         Ipv6Addr::UNSPECIFIED.into()
      };
      let socket = Socket::open(SocketAddr::new(unspecified, 0), Some(remote))?;

      let mut config = ClientConfig::new(crypto);
      config.transport_config(self.tuning.transport(socket.payload_bound(remote)?));

      let (handle, connection) = self
         .endpoint
         .connect(now, config, remote, server_name)
         .map_err(Error::Connect)?;

      self.sessions.insert(handle, Session {
         connection,
         socket,
         window_floor,
      });
      Ok(handle)
   }

   /// Drives every connection until `app` reports it is done.
   ///
   /// # Errors
   ///
   /// Returns the first socket failure or the first error from `app`.
   pub fn run<A: App>(&mut self, app: &mut A) -> Result<(), A::Error> {
      let mut handles = Vec::new();

      loop {
         let now = Instant::now();

         handles.clear();
         handles.extend(self.sessions.keys().copied());

         self.receive(now, Source::Listener)?;

         for &handle in &handles {
            self.receive(now, Source::Session(handle))?;
         }

         let mut deadline: Option<Instant> = None;

         for (&handle, session) in &mut self.sessions {
            let connection = &mut session.connection;

            if connection.poll_timeout().is_some_and(|at| at <= now) {
               connection.handle_timeout(now);
            }

            // Unsent data beyond two round trips overflows the receiver's
            // socket buffer and delays every stream on the connection, so the
            // window tracks the path's minimum RTT.
            #[expect(
               clippy::cast_possible_truncation,
               clippy::cast_sign_loss,
               reason = "the product is positive and clamped below 2^26"
            )]
            let window =
               (connection.stats().path.min_rtt.as_secs_f64() * 2.0 * RATE_CEILING) as u64;
            connection.set_send_window(window.clamp(session.window_floor, SEND_WINDOW_CEILING));

            while let Some(event) = connection.poll() {
               app.event(now, handle, connection, event)?;
            }

            let wake = app.tick(now, handle, connection)?;
            let backlog = session.flush(now, handle, &mut self.endpoint, &mut self.send)?;

            for at in [
               wake,
               session.connection.poll_timeout(),
               backlog.then_some(now),
            ]
            .into_iter()
            .flatten()
            {
               deadline = Some(deadline.map_or(at, |current| current.min(at)));
            }
         }

         if app.done() {
            return Ok(());
         }

         self
            .sessions
            .retain(|_, session| !session.connection.is_drained());
         self.wait(deadline)?;
      }
   }

   fn wait(&self, deadline: Option<Instant>) -> Result<(), Error> {
      let timeout = deadline.map(|at| {
         let wait = at.saturating_duration_since(Instant::now());

         Timespec {
            tv_sec:  i64::try_from(wait.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: wait.subsec_nanos().into(),
         }
      });

      let mut sockets: Vec<_> = self
         .listener
         .iter()
         .map(|listener| &listener.socket)
         .chain(self.sessions.values().map(|session| &session.socket))
         .map(|socket| PollFd::new(&socket.io, PollFlags::IN))
         .collect();

      poll(&mut sockets, timeout.as_ref()).map_err(|errno| Error::Poll(errno.into()))?;
      Ok(())
   }

   fn receive(&mut self, now: Instant, source: Source) -> Result<(), Error> {
      let mut metas = [RecvMeta::default(); BATCH_SIZE];

      for _ in 0..RECV_ROUNDS {
         let socket = match source {
            Source::Listener => self.listener.as_ref().map(|listener| &listener.socket),
            Source::Session(handle) => self.sessions.get(&handle).map(|session| &session.socket),
         };

         let Some(count) = socket
            .map(|socket| socket.receive(&mut self.recv, &mut metas))
            .transpose()?
            .flatten()
         else {
            return Ok(());
         };

         for (index, meta) in metas.iter().enumerate().take(count) {
            let mut batch = BytesMut::from(&self.recv[index * RECV_LEN..][..meta.len]);

            while !batch.is_empty() {
               let datagram = batch.split_to(meta.stride.min(batch.len()));
               self.dispatch(now, meta, datagram)?;
            }
         }
      }

      Ok(())
   }

   fn dispatch(&mut self, now: Instant, meta: &RecvMeta, datagram: BytesMut) -> Result<(), Error> {
      let ecn = meta
         .ecn
         .and_then(|codepoint| EcnCodepoint::from_bits(codepoint as u8));

      self.send.clear();
      let event = self
         .endpoint
         .handle(now, meta.addr, meta.dst_ip, ecn, datagram, &mut self.send);

      match event {
         Some(DatagramEvent::ConnectionEvent(handle, event)) => {
            if let Some(session) = self.sessions.get_mut(&handle) {
               session.connection.handle_event(event);
            }

            Ok(())
         },
         Some(DatagramEvent::NewConnection(incoming)) => self.accept(now, incoming),
         Some(DatagramEvent::Response(response)) => self.respond(&response),
         None => Ok(()),
      }
   }

   fn accept(&mut self, now: Instant, incoming: Incoming) -> Result<(), Error> {
      let Some(listener) = &self.listener else {
         self.endpoint.ignore(incoming);
         return Ok(());
      };

      // The reply must leave from the address the client sent to, so the
      // connected socket binds that address when the kernel reported it.
      let remote = incoming.remote_address();
      let local = SocketAddr::new(
         incoming.local_ip().unwrap_or_else(|| listener.local.ip()),
         listener.local.port(),
      );

      let Ok(socket) = Socket::open(local, Some(remote)) else {
         let refusal = self.endpoint.refuse(incoming, &mut self.send);
         return listener.socket.transmit(&refusal, &self.send);
      };

      let mut config = listener.config.clone();
      config.transport_config(self.tuning.transport(socket.payload_bound(remote)?));

      match self
         .endpoint
         .accept(incoming, now, &mut self.send, Some(Arc::new(config)))
      {
         Ok((handle, connection)) => {
            let session = Session {
               connection,
               socket,
               window_floor: INTERACTIVE_WINDOW,
            };
            self.sessions.insert(handle, session);
            Ok(())
         },
         Err(error) => {
            match error.response {
               Some(response) => listener.socket.transmit(&response, &self.send),
               None => Ok(()),
            }
         },
      }
   }

   fn respond(&self, response: &Transmit) -> Result<(), Error> {
      let socket = self.listener.as_ref().map_or_else(
         || {
            self
               .sessions
               .values()
               .find(|session| session.connection.remote_address() == response.destination)
               .map(|session| &session.socket)
         },
         |listener| Some(&listener.socket),
      );

      socket.map_or(Ok(()), |socket| socket.transmit(response, &self.send))
   }
}
