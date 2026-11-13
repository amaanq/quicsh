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
   collections::BTreeMap,
   fmt::{
      self,
      Display,
      Formatter,
   },
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
   os::fd::{
      AsFd,
      BorrowedFd,
      OwnedFd,
   },
   str::FromStr,
   sync::Arc,
   time::{
      Duration,
      Instant,
   },
};

use bytes::{
   Bytes,
   BytesMut,
};
use quinn_proto::{
   ClientConfig,
   Connection,
   ConnectionHandle,
   DatagramEvent,
   EcnCodepoint,
   Endpoint,
   EndpointConfig,
   Event,
   HashedConnectionIdGenerator,
   Incoming,
   MtuDiscoveryConfig,
   ReadError,
   ServerConfig,
   StreamId,
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
use ring::hmac;
use rustix::{
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   io::{
      Errno,
      ioctl_fionbio,
   },
   net::{
      AddressFamily,
      RecvFlags,
      SendFlags,
      SocketFlags,
      SocketType,
      bind,
      connect,
      netlink::SocketAddrNetlink,
      recv,
      send,
      socket_with,
      sockopt::{
         ip_mtu,
         ipv6_mtu,
         set_ipv6_v6only,
         set_socket_reuseport,
      },
   },
   time::Timespec,
};

use crate::{
   error::Error,
   pipe::Waker,
};

/// Send window floor for a connection that carries keystrokes.
pub const INTERACTIVE_WINDOW: u64 = 256 << 10;

/// Largest datagram batch one receive slot holds.
const RECV_LEN: usize = 1 << 16;
/// Kernel buffer size requested for each socket.
const SOCKET_BUFFER: usize = 4 << 20;
/// Receive batches taken from one socket per loop turn.
const RECV_ROUNDS: usize = 8;
/// Datagram batches sent for one connection per loop turn.
const SEND_ROUNDS: usize = 64;
/// Largest send window.
const SEND_WINDOW_CEILING: u64 = 64 << 20;
/// Rate the send window is sized for, in bytes per second.
const RATE_CEILING: f64 = 10.0e9 / 8.0;
/// Smallest UDP payload QUIC allows.
const MIN_UDP_PAYLOAD: u16 = 1200;
/// Largest UDP payload over IPv6.
const MAX_UDP_PAYLOAD: u16 = u16::MAX - 8;
/// Largest UDP payload over IPv4.
const MAX_UDP_PAYLOAD_V4: u16 = 65507;
/// Idle time after which a connection is closed.
const IDLE_TIMEOUT_MS: u32 = 60_000;
/// Gap between keep-alive packets.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// Handshakes allowed in progress at once.
const MAX_HANDSHAKES: usize = 64;
/// Silence from the peer before a dialed connection tests its path.
const PATIENCE: Duration = Duration::from_secs(1);
/// Longest gap between attempts to move a silent connection to a new socket.
const PATIENCE_CEILING: Duration = Duration::from_secs(8);
/// The `RTMGRP` netlink groups for IPv4 and IPv6 address and route changes.
const NETWORK_CHANGES: u32 = 0x10 | 0x40 | 0x100 | 0x400;

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

impl Display for Congestion {
   fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      formatter.write_str(match *self {
         Self::Bbr => "bbr",
         Self::Cubic => "cubic",
      })
   }
}

impl Congestion {
   /// The QUIC transport settings for a path with this payload bound.
   fn transport(self, route_bound: u16) -> Arc<TransportConfig> {
      let mut discovery = MtuDiscoveryConfig::default();
      discovery.upper_bound(route_bound);

      let mut transport = TransportConfig::default();

      transport
         .stream_receive_window(VarInt::from_u32(16 << 20))
         .receive_window(VarInt::from_u32(64 << 20))
         .send_window(INTERACTIVE_WINDOW)
         .max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
         .keep_alive_interval(Some(KEEP_ALIVE))
         .mtu_discovery_config(Some(discovery));

      match self {
         Self::Bbr => transport.congestion_controller_factory(Arc::new(BbrConfig::default())),
         Self::Cubic => transport.congestion_controller_factory(Arc::new(CubicConfig::default())),
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

   /// Runs once per loop iteration after every [`App::tick`], also when
   /// there is no connection, and returns the next instant the app wants to
   /// run at.
   ///
   /// # Errors
   ///
   /// An error stops [`Transport::run`].
   fn idle(&mut self, _now: Instant) -> Result<Option<Instant>, Self::Error> {
      Ok(None)
   }

   fn done(&self) -> bool;

   /// A waker whose signal should also end the loop's wait. The loop clears
   /// it before it calls the app.
   fn waker(&self) -> Option<&Waker> {
      None
   }
}

/// Takes everything a stream has buffered. The flag reports that the peer
/// finished the stream.
///
/// # Errors
///
/// Fails when the peer reset the stream.
pub fn drain(connection: &mut Connection, id: StreamId) -> Result<(Vec<Bytes>, bool), Error> {
   let mut received = Vec::new();
   let mut stream = connection.recv_stream(id);
   let Ok(mut chunks) = stream.read(true) else {
      return Ok((received, false));
   };

   let finished = loop {
      match chunks.next(usize::MAX) {
         Ok(Some(chunk)) => received.push(chunk.bytes),
         Ok(None) => break true,
         Err(ReadError::Blocked) => break false,
         Err(error) => return Err(Error::Read(error)),
      }
   };

   let _ = chunks.finalize();
   Ok((received, finished))
}

/// A UDP socket bound to `local` that shares the port with other sockets,
/// and connected to `remote` when one is given. An IPv6 `local` accepts IPv4
/// peers too.
///
/// # Errors
///
/// Fails when the address cannot be bound, as for a port under 1024 without
/// the privilege to use it.
pub fn udp_socket(local: SocketAddr, remote: Option<SocketAddr>) -> io::Result<OwnedFd> {
   let family = if local.is_ipv4() {
      AddressFamily::INET
   } else {
      AddressFamily::INET6
   };

   let fd = socket_with(family, SocketType::DGRAM, SocketFlags::CLOEXEC, None)?;
   set_socket_reuseport(&fd, true)?;

   // An IPv6 socket also carries IPv4, as IPv4-mapped addresses, whatever
   // the `net.ipv6.bindv6only` sysctl says.
   if local.is_ipv6() {
      set_ipv6_v6only(&fd, false)?;
   }

   bind(&fd, &local)?;

   if let Some(peer) = remote {
      connect(&fd, &peer)?;
   }

   Ok(fd)
}

/// Opens a netlink socket that turns readable when an address or a route
/// changes.
fn network_changes() -> io::Result<OwnedFd> {
   let fd = socket_with(
      AddressFamily::NETLINK,
      SocketType::RAW,
      SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
      None,
   )?;

   bind(&fd, &SocketAddrNetlink::new(0, NETWORK_CHANGES))?;
   Ok(fd)
}

/// Makes the socket for one accepted connection, bound to the first address
/// and connected to the second.
pub type Opener = Box<dyn Fn(SocketAddr, SocketAddr) -> io::Result<OwnedFd>>;

/// What a connection sends its datagrams through.
enum Socket {
   /// A UDP socket.
   Udp {
      /// The socket.
      io:    UdpSocket,
      /// What the kernel supports for segmentation and receive batching.
      state: UdpSocketState,
   },
   /// A socket pair whose other end relays each message as a datagram, which
   /// is how a connection runs through a jump host.
   Pipe {
      /// This side of the pair.
      io:   OwnedFd,
      /// The address the connection believes its peer has.
      peer: SocketAddr,
   },
}

impl AsFd for Socket {
   fn as_fd(&self) -> BorrowedFd<'_> {
      match *self {
         Self::Udp { ref io, .. } => io.as_fd(),
         Self::Pipe { ref io, .. } => io.as_fd(),
      }
   }
}

impl Socket {
   /// Opens a socket bound to `local`.
   fn open(local: SocketAddr, remote: Option<SocketAddr>) -> Result<Self, Error> {
      Self::adopt(udp_socket(local, remote).map_err(Error::Socket)?)
   }

   /// Opens a socket connected to `peer` from whichever address routes there.
   fn dial(peer: SocketAddr) -> Result<Self, Error> {
      let unspecified = if peer.is_ipv4() {
         Ipv4Addr::UNSPECIFIED.into()
      } else {
         Ipv6Addr::UNSPECIFIED.into()
      };

      Self::open(SocketAddr::new(unspecified, 0), Some(peer))
   }

   /// Takes over a socket that is already bound.
   fn adopt(fd: OwnedFd) -> Result<Self, Error> {
      let setup = || {
         let io = UdpSocket::from(fd);
         let state = UdpSocketState::new((&io).into())?;
         state.set_send_buffer_size((&io).into(), SOCKET_BUFFER)?;
         state.set_recv_buffer_size((&io).into(), SOCKET_BUFFER)?;

         io::Result::Ok(Self::Udp { io, state })
      };

      setup().map_err(Error::Socket)
   }

   /// The local address a UDP socket sends from.
   fn source(&self) -> Option<IpAddr> {
      match *self {
         Self::Udp { ref io, .. } => io.local_addr().ok().map(|local| local.ip()),
         Self::Pipe { .. } => None,
      }
   }

   /// Most datagrams one send may carry.
   fn segments(&self) -> usize {
      match *self {
         Self::Udp { ref state, .. } => state.max_gso_segments(),
         Self::Pipe { .. } => 1,
      }
   }

   /// Largest UDP payload that fits the route this connected socket uses. A
   /// relayed connection cannot see its route, so it probes up to the most a
   /// datagram holds and the relay drops what does not fit.
   fn payload_bound(&self, remote: SocketAddr) -> Result<u16, Error> {
      let Self::Udp { ref io, .. } = *self else {
         return Ok(MAX_UDP_PAYLOAD_V4);
      };

      // An IPv4 peer of an IPv6 socket has an IPv4-mapped address and still
      // travels in IPv4 packets.
      let (mtu, overhead, ceiling) = if remote.ip().to_canonical().is_ipv4() {
         (ip_mtu(io), 28, MAX_UDP_PAYLOAD_V4)
      } else {
         (ipv6_mtu(io), 48, MAX_UDP_PAYLOAD)
      };

      let payload = mtu
         .map_err(|errno| Error::Socket(errno.into()))?
         .saturating_sub(overhead);

      Ok(u16::try_from(payload).map_or(ceiling, |fits| fits.clamp(MIN_UDP_PAYLOAD, ceiling)))
   }

   /// Returns the number of filled buffers, or `None` when the socket has
   /// nothing queued.
   fn receive(
      &self,
      buffer: &mut [u8],
      metas: &mut [RecvMeta; BATCH_SIZE],
   ) -> Result<Option<usize>, Error> {
      let (io, state) = match *self {
         Self::Udp { ref io, ref state } => (io, state),
         Self::Pipe { ref io, peer } => {
            return match recv(io, &mut buffer[..RECV_LEN], RecvFlags::DONTWAIT) {
               Ok((0, _)) => Err(Error::Receive(io::ErrorKind::UnexpectedEof.into())),
               Ok((len, _)) => {
                  let meta = &mut metas[0];
                  meta.addr = peer;
                  meta.len = len;
                  meta.stride = len;
                  meta.ecn = None;
                  meta.dst_ip = None;

                  Ok(Some(1))
               },
               Err(Errno::WOULDBLOCK | Errno::INTR) => Ok(None),
               Err(errno) => Err(Error::Receive(errno.into())),
            };
         },
      };

      let mut slices = buffer
         .chunks_mut(RECV_LEN)
         .map(IoSliceMut::new)
         .collect::<Vec<IoSliceMut>>();

      match state.recv(io.into(), &mut slices, metas) {
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

   /// Sends one batch of datagrams.
   fn transmit(&self, meta: &Transmit, contents: &[u8]) -> Result<(), Error> {
      let (io, state) = match *self {
         Self::Udp { ref io, ref state } => (io, state),
         Self::Pipe { ref io, .. } => {
            let size = meta.segment_size.unwrap_or(meta.size).max(1);

            for datagram in contents[..meta.size].chunks(size) {
               loop {
                  match send(io, datagram, SendFlags::NOSIGNAL) {
                     Ok(_) | Err(Errno::MSGSIZE) => break,
                     Err(Errno::WOULDBLOCK) => {
                        poll(&mut [PollFd::new(io, PollFlags::OUT)], None)
                           .map_err(|errno| Error::Poll(errno.into()))?;
                     },
                     Err(Errno::INTR) => {},
                     Err(errno) => return Err(Error::Send(errno.into())),
                  }
               }
            }

            return Ok(());
         },
      };

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
         match state.try_send(io.into(), &datagrams) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
               poll(&mut [PollFd::new(io, PollFlags::OUT)], None)
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

/// Watches the path of a dialed connection for silence.
///
/// A laptop that changes networks keeps a socket whose source address no
/// longer exists. The kernel reports local changes, but a path can also die
/// further away, where the only evidence is a peer that stopped answering.
struct Probe {
   /// When the oldest packet the peer has not answered went out.
   unanswered: Option<Instant>,
   /// Whether a ping already tested this silence.
   pinged:     bool,
   /// How long the silence lasts before the next step.
   patience:   Duration,
}

impl Default for Probe {
   fn default() -> Self {
      Self {
         unanswered: None,
         pinged:     false,
         patience:   PATIENCE,
      }
   }
}

/// Which side started a connection, which decides how it follows its peer.
enum Role {
   /// This side dialed, so it moves to a new socket when the path goes silent.
   Dialed(Probe),
   /// The peer dialed, so the socket follows the address the peer sends from.
   Accepted,
}

/// One connection and the socket it owns.
struct Session {
   /// The QUIC state machine.
   connection:   Connection,
   /// The connected socket.
   socket:       Socket,
   /// The address the socket is connected to.
   peer:         SocketAddr,
   /// Which side dialed.
   role:         Role,
   /// Smallest send window this connection gets.
   window_floor: u64,
}

impl Session {
   /// Notes that the peer answered.
   fn heard(&mut self) {
      if let Role::Dialed(ref mut probe) = self.role {
         *probe = Probe::default();
      }
   }

   /// Reacts to a local address or route change. Moves to a new socket when
   /// the route to the peer now leaves from another address, and tests the
   /// path with a ping otherwise.
   fn moved(&mut self) {
      let Role::Dialed(ref mut probe) = self.role else {
         return;
      };

      // The relay of a connection without a UDP socket follows the network.
      let fresh = matches!(self.socket, Socket::Udp { .. })
         .then(|| Socket::dial(self.peer).ok())
         .flatten()
         .filter(|socket| socket.source() != self.socket.source());

      if let Some(socket) = fresh {
         self.socket = socket;
         self.connection.local_address_changed();
      } else {
         self.connection.ping();
      }

      probe.pinged = true;
   }

   /// Tests a silent path with a ping, then moves to a new socket each time
   /// the silence lasts. Returns when to look again.
   fn probe(&mut self, now: Instant) -> Option<Instant> {
      let Role::Dialed(ref mut probe) = self.role else {
         return None;
      };

      let patience = probe.patience.max(self.connection.rtt() * 3);
      let due = probe.unanswered? + patience;

      if now < due {
         return Some(due);
      }

      if probe.pinged {
         // Opening fails while no network reaches the peer, and the next
         // attempt may find one.
         if matches!(self.socket, Socket::Udp { .. })
            && let Ok(socket) = Socket::dial(self.peer)
         {
            self.socket = socket;
            self.connection.local_address_changed();
         }

         probe.patience = (probe.patience * 2).min(PATIENCE_CEILING);
      } else {
         self.connection.ping();
         probe.pinged = true;
      }

      probe.unanswered = Some(now);
      Some(now + probe.patience)
   }

   /// Moves an accepted connection's socket to the address its peer now
   /// sends from, so a client that changed networks keeps a queue of its own.
   fn follow(&mut self, listener: &Listener) {
      let remote = self.connection.remote_address();

      if !matches!(self.role, Role::Accepted) || remote == self.peer {
         return;
      }

      self.peer = remote;

      let local = listener.bound(self.connection.local_ip(), remote);
      let opened = (listener.opener)(local, remote)
         .ok()
         .and_then(|fd| Socket::adopt(fd).ok());

      if let Some(socket) = opened {
         self.socket = socket;
      }
   }

   /// Returns whether the connection still has packets to send. A failed send
   /// counts as a lost packet, which the connection recovers from or times
   /// out on.
   fn flush(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      endpoint: &mut Endpoint,
      buffer: &mut Vec<u8>,
   ) -> bool {
      for _ in 0..SEND_ROUNDS {
         while let Some(event) = self.connection.poll_endpoint_events() {
            if let Some(reply) = endpoint.handle_event(handle, event) {
               self.connection.handle_event(reply);
            }
         }

         // The kernel rejects a GSO send whose segments total more than one UDP
         // payload.
         let mtu = usize::from(self.connection.current_mtu());
         let segments = (usize::from(MAX_UDP_PAYLOAD_V4) / mtu).clamp(1, self.socket.segments());

         buffer.clear();
         let Some(meta) = self.connection.poll_transmit(now, segments, buffer) else {
            return false;
         };

         let sent = self.socket.transmit(&meta, buffer);

         if let Role::Dialed(ref mut probe) = self.role {
            probe.unanswered.get_or_insert(now);
            probe.pinged |= sent.is_err();
         }

         if sent.is_err() {
            return false;
         }
      }

      true
   }
}

/// What accepting connections needs.
struct Listener {
   /// The socket that receives first packets.
   socket: Socket,
   /// The address it is bound to.
   local:  SocketAddr,
   /// TLS and transport settings for new connections.
   config: ServerConfig,
   /// Makes the socket for each new connection.
   opener: Opener,
}

impl Listener {
   /// The address a connection's socket binds, given where the peer sent to
   /// and from. A reply must leave from the address the peer sent to.
   fn bound(&self, destination: Option<IpAddr>, remote: SocketAddr) -> SocketAddr {
      // The kernel reports an IPv4 destination in IPv4 form even on an IPv6
      // socket, which can bind only the mapped form.
      let ip = match (destination.unwrap_or_else(|| self.local.ip()), remote) {
         (IpAddr::V4(address), SocketAddr::V6(_)) => address.to_ipv6_mapped().into(),
         (address, _) => address,
      };

      SocketAddr::new(ip, self.local.port())
   }
}

/// Where a datagram batch came from.
#[derive(Clone, Copy)]
enum Source {
   /// The listening socket.
   Listener,
   /// A connection's own socket.
   Session(ConnectionHandle),
}

pub struct Transport {
   /// Routes datagrams to connections.
   endpoint:   Endpoint,
   /// Present when the transport accepts connections.
   listener:   Option<Listener>,
   /// Every live connection.
   sessions:   BTreeMap<ConnectionHandle, Session>,
   /// Settings for new connections.
   congestion: Congestion,
   /// Turns readable when a local address or route changes. Present once the
   /// transport has dialed a connection.
   changes:    Option<OwnedFd>,
   /// Receive buffer.
   recv:       Vec<u8>,
   /// Send buffer.
   send:       Vec<u8>,
}

impl Transport {
   /// A transport that only makes outgoing connections.
   ///
   /// # Errors
   ///
   /// Fails when the endpoint rejects its configuration.
   pub fn new(congestion: Congestion) -> Result<Self, Error> {
      Self::build(None, congestion, None)
   }

   /// A transport that accepts connections on `socket`, which is bound to
   /// `local`, and gets each connection's own socket from `opener`.
   ///
   /// # Errors
   ///
   /// Fails when `socket` is not a usable UDP socket.
   pub fn adopt(
      socket: OwnedFd,
      local: SocketAddr,
      crypto: Arc<QuicServerConfig>,
      congestion: Congestion,
      opener: Opener,
      secret: &[u8],
   ) -> Result<Self, Error> {
      let listener = Listener {
         socket: Socket::adopt(socket)?,
         local,
         config: ServerConfig::with_crypto(crypto),
         opener,
      };

      Self::build(Some(listener), congestion, Some(secret))
   }

   /// Builds the endpoint around an optional listener.
   fn build(
      listener: Option<Listener>,
      congestion: Congestion,
      restart: Option<&[u8]>,
   ) -> Result<Self, Error> {
      let mut config = EndpointConfig::default();

      // A restarted server must recognize the old one's connection IDs and
      // sign the same reset tokens, or its clients wait out the idle timeout.
      if let Some(secret) = restart {
         let ids = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, secret),
            b"connection ids",
         );
         let seed = ids
            .as_ref()
            .first_chunk()
            .map_or(0, |bytes| u64::from_be_bytes(*bytes));

         config
            .reset_key(Arc::new(hmac::Key::new(hmac::HMAC_SHA256, secret)))
            .cid_generator(move || Box::new(HashedConnectionIdGenerator::from_key(seed)));
      }

      config
         .max_udp_payload_size(MAX_UDP_PAYLOAD)
         .map_err(Error::Config)?;

      let server = listener
         .as_ref()
         .map(|accepting| Arc::new(accepting.config.clone()));

      Ok(Self {
         endpoint: Endpoint::new(Arc::new(config), server, true, None),
         listener,
         sessions: BTreeMap::new(),
         congestion,
         changes: None,
         recv: vec![0; RECV_LEN * BATCH_SIZE],
         send: Vec::with_capacity(RECV_LEN),
      })
   }

   /// Starts a connection to `remote` on a socket of its own. With `link`,
   /// the datagrams travel as messages on that socket pair, and `remote` is
   /// only a name for whoever answers at its other end.
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
      link: Option<OwnedFd>,
   ) -> Result<ConnectionHandle, Error> {
      if self.changes.is_none() {
         self.changes = Some(network_changes().map_err(Error::Socket)?);
      }

      let socket = match link {
         Some(io) => {
            ioctl_fionbio(&io, true).map_err(|errno| Error::Socket(errno.into()))?;
            Socket::Pipe { io, peer: remote }
         },
         None => Socket::dial(remote)?,
      };

      let mut config = ClientConfig::new(crypto);
      config.transport_config(self.congestion.transport(socket.payload_bound(remote)?));

      let (handle, connection) = self
         .endpoint
         .connect(now, config, remote, server_name)
         .map_err(Error::Connect)?;

      self.sessions.insert(handle, Session {
         connection,
         socket,
         peer: remote,
         role: Role::Dialed(Probe::default()),
         window_floor,
      });
      Ok(handle)
   }

   /// Drives every connection until `app` reports it is done.
   ///
   /// # Errors
   ///
   /// Returns the first socket failure or the first error from `app`.
   pub fn run<A>(&mut self, app: &mut A) -> Result<(), A::Error>
   where
      A: App,
   {
      let mut handles = Vec::new();

      loop {
         let now = Instant::now();

         // Clearing before any work means a signal that arrives during the
         // work ends the next wait.
         if let Some(waker) = app.waker() {
            waker.clear();
         }

         handles.clear();
         handles.extend(self.sessions.keys().copied());

         self.receive(now, Source::Listener)?;

         for &handle in &handles {
            self.receive(now, Source::Session(handle))?;
         }

         let moved = self.changed()?;
         let mut deadline = Option::<Instant>::None;

         for (&handle, session) in &mut self.sessions {
            if let Some(ref listener) = self.listener {
               session.follow(listener);
            }

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

            if moved {
               session.moved();
            }

            let silence = session.probe(now);
            let backlog = session.flush(now, handle, &mut self.endpoint, &mut self.send);

            for at in [
               wake,
               silence,
               session.connection.poll_timeout(),
               backlog.then_some(now),
            ]
            .into_iter()
            .flatten()
            {
               deadline = Some(deadline.map_or(at, |current| current.min(at)));
            }
         }

         if let Some(at) = app.idle(now)? {
            deadline = Some(deadline.map_or(at, |current| current.min(at)));
         }

         if app.done() {
            return Ok(());
         }

         self
            .sessions
            .retain(|_, session| !session.connection.is_drained());
         self.wait(deadline, app.waker())?;
      }
   }

   /// Drains the netlink socket and returns whether it reported a change.
   fn changed(&mut self) -> Result<bool, Error> {
      let Some(ref netlink) = self.changes else {
         return Ok(false);
      };

      let mut seen = false;

      loop {
         match recv(netlink, self.recv.as_mut_slice(), RecvFlags::empty()) {
            // ENOBUFS means the queue overflowed and the kernel dropped
            // messages, which is still a change.
            Ok(_) | Err(Errno::NOBUFS) => seen = true,
            Err(Errno::WOULDBLOCK) => return Ok(seen),
            Err(errno) => return Err(Error::Receive(errno.into())),
         }
      }
   }

   /// Sleeps until a socket is readable, the waker fires or `deadline` passes.
   fn wait(&self, deadline: Option<Instant>, waker: Option<&Waker>) -> Result<(), Error> {
      let timeout = deadline.map(|at| {
         let wait = at.saturating_duration_since(Instant::now());

         Timespec {
            tv_sec:  i64::try_from(wait.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: wait.subsec_nanos().into(),
         }
      });

      let mut sockets = self
         .listener
         .iter()
         .map(|listener| &listener.socket)
         .chain(self.sessions.values().map(|session| &session.socket))
         .map(|socket| PollFd::new(socket, PollFlags::IN))
         .chain(waker.map(|eventfd| PollFd::new(eventfd, PollFlags::IN)))
         .chain(
            self
               .changes
               .iter()
               .map(|netlink| PollFd::new(netlink, PollFlags::IN)),
         )
         .collect::<Vec<PollFd>>();

      match poll(&mut sockets, timeout.as_ref()) {
         // A signal handler ran. The caller's tick decides what that means.
         Ok(_) | Err(Errno::INTR) => Ok(()),
         Err(errno) => Err(Error::Poll(errno.into())),
      }
   }

   /// Reads and dispatches what one socket has queued.
   fn receive(&mut self, now: Instant, source: Source) -> Result<(), Error> {
      let mut metas = [RecvMeta::default(); BATCH_SIZE];

      for _ in 0..RECV_ROUNDS {
         let socket = match source {
            Source::Listener => self.listener.as_ref().map(|listener| &listener.socket),
            Source::Session(handle) => self.sessions.get(&handle).map(|session| &session.socket),
         };

         let Some(count) = socket
            .map(|readable| readable.receive(&mut self.recv, &mut metas))
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

   /// Hands one datagram to the endpoint and acts on its answer.
   fn dispatch(&mut self, now: Instant, meta: &RecvMeta, datagram: BytesMut) -> Result<(), Error> {
      let ecn = meta
         .ecn
         .and_then(|codepoint| EcnCodepoint::from_bits(codepoint as u8));

      self.send.clear();
      let event = self
         .endpoint
         .handle(now, meta.addr, meta.dst_ip, ecn, datagram, &mut self.send);

      match event {
         Some(DatagramEvent::ConnectionEvent(target, routed)) => {
            if let Some(session) = self.sessions.get_mut(&target) {
               session.connection.handle_event(routed);
               session.heard();
            }

            Ok(())
         },
         Some(DatagramEvent::NewConnection(incoming)) => self.accept(now, incoming),
         Some(DatagramEvent::Response(response)) => self.respond(&response),
         None => Ok(()),
      }
   }

   /// Accepts or refuses a new connection.
   fn accept(&mut self, now: Instant, incoming: Incoming) -> Result<(), Error> {
      let Some(ref listener) = self.listener else {
         self.endpoint.ignore(incoming);
         return Ok(());
      };

      let remote = incoming.remote_address();
      let local = listener.bound(incoming.local_ip(), remote);

      // Each handshake costs a signature and a socket before the client has
      // proved anything, so a flood of first packets is cut off here.
      let handshaking = self
         .sessions
         .values()
         .filter(|session| session.connection.is_handshaking())
         .count();

      let opened = (handshaking < MAX_HANDSHAKES)
         .then(|| (listener.opener)(local, remote).ok())
         .flatten()
         .and_then(|fd| Socket::adopt(fd).ok());

      let Some(socket) = opened else {
         let refusal = self.endpoint.refuse(incoming, &mut self.send);
         return listener.socket.transmit(&refusal, &self.send);
      };

      let mut config = listener.config.clone();
      config.transport_config(self.congestion.transport(socket.payload_bound(remote)?));

      match self
         .endpoint
         .accept(incoming, now, &mut self.send, Some(Arc::new(config)))
      {
         Ok((handle, connection)) => {
            let session = Session {
               connection,
               socket,
               peer: remote,
               role: Role::Accepted,
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

   /// Sends a stateless reply from the endpoint.
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

      socket.map_or(Ok(()), |chosen| chosen.transmit(response, &self.send))
   }
}
