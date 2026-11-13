//! Listening and dialing for port and agent forwarding.
//!
//! Accepting and connecting block, so each runs on a thread and hands its
//! sockets to the event loop through a channel and a [`Waker`].
//!
//! A UDP socket is forwarded as a byte stream of length-prefixed datagrams,
//! which is what carries a connection to a server behind a jump host.

use std::{
   fs::{
      self,
      Permissions,
   },
   io::{
      self,
      Read as _,
      Write as _,
   },
   mem,
   net::{
      Ipv4Addr,
      Ipv6Addr,
      SocketAddr,
      TcpListener,
      TcpStream,
      ToSocketAddrs as _,
      UdpSocket,
   },
   os::{
      fd::OwnedFd,
      unix::{
         fs::{
            FileTypeExt as _,
            MetadataExt as _,
            PermissionsExt as _,
         },
         net::{
            UnixListener,
            UnixStream,
         },
      },
   },
   path::{
      Path,
      PathBuf,
   },
   sync::{
      Arc,
      atomic::{
         AtomicBool,
         Ordering,
      },
      mpsc::{
         Receiver,
         TryRecvError,
         channel,
      },
   },
   thread,
   time::Duration,
};

use quinn_proto::{
   Connection,
   StreamId,
};
use quinn_udp::UdpSocketState;
use rustix::{
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   io::Errno,
   net::{
      AddressFamily,
      RecvFlags,
      SendFlags,
      Shutdown,
      SocketAddrUnix,
      SocketFlags,
      SocketType,
      bind,
      listen,
      recv,
      send,
      shutdown,
      socket_with,
   },
   time::Timespec,
};

use crate::{
   control::Message,
   error::Error,
   pipe::{
      Waker,
      receive_message,
   },
   relay::Relay,
};

/// Pause after a failed accept.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);
/// Connections a forwarded Unix socket holds before one is accepted.
const UNIX_BACKLOG: i32 = 128;

/// A listening socket whose accepted connections arrive on a channel.
/// Dropping it stops the listener.
pub struct Acceptor {
   /// Connections the accept thread has taken.
   incoming: Receiver<OwnedFd>,
   /// The listening socket, kept to shut it down.
   listener: OwnedFd,
   /// Tells the accept thread to stop.
   closed:   Arc<AtomicBool>,
}

impl Acceptor {
   /// Listens on `address` and returns the port that was bound, which differs
   /// from the request when that asked for port 0.
   ///
   /// # Errors
   ///
   /// Fails when the address cannot be bound.
   pub fn tcp(address: SocketAddr, waker: &Arc<Waker>) -> Result<(Self, u16), Error> {
      let listener = TcpListener::bind(address).map_err(Error::Forward)?;
      let port = listener.local_addr().map_err(Error::Forward)?.port();
      let handle = listener.try_clone().map_err(Error::Forward)?.into();

      let accept = move || {
         let (stream, _) = listener.accept()?;
         stream.set_nodelay(true)?;
         Ok(OwnedFd::from(stream))
      };

      Ok((Self::spawn(handle, accept, waker), port))
   }

   /// Accepts on a Unix socket that is already listening.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn unix(listener: UnixListener, waker: &Arc<Waker>) -> Result<Self, Error> {
      let handle = listener.try_clone().map_err(Error::Forward)?.into();
      let accept = move || Ok(OwnedFd::from(listener.accept()?.0));

      Ok(Self::spawn(handle, accept, waker))
   }

   /// Starts the thread that accepts on `listener`.
   fn spawn(
      listener: OwnedFd,
      mut accept: impl FnMut() -> io::Result<OwnedFd> + Send + 'static,
      waker: &Arc<Waker>,
   ) -> Self {
      let (accepted, incoming) = channel();
      let closed = Arc::new(AtomicBool::new(false));
      let stop = Arc::clone(&closed);
      let notifier = Arc::clone(waker);

      thread::spawn(move || {
         while !stop.load(Ordering::Relaxed) {
            match accept() {
               Ok(socket) => {
                  if accepted.send(socket).is_err() {
                     break;
                  }

                  notifier.wake();
               },
               // A failed accept is usually one aborted connection or a
               // briefly full descriptor table.
               Err(_) => thread::sleep(ACCEPT_RETRY),
            }
         }
      });

      Self {
         incoming,
         listener,
         closed,
      }
   }

   /// The next accepted connection, if one is waiting.
   #[must_use]
   pub fn poll(&self) -> Option<OwnedFd> {
      self.incoming.try_recv().ok()
   }
}

impl Drop for Acceptor {
   fn drop(&mut self) {
      // Shutting the socket down makes the blocked accept call return, which
      // closing this descriptor alone would not.
      self.closed.store(true, Ordering::Relaxed);
      let _ = shutdown(&self.listener, Shutdown::Both);
   }
}

/// A Unix socket file that is removed with this value.
pub struct Bound {
   /// Where the socket is.
   path:  PathBuf,
   /// Device and inode of the socket file. A file that took its place
   /// stays.
   named: (u64, u64),
}

impl Bound {
   /// Listens at `path`, which only the owner may connect to. A socket file
   /// that nobody listens on any more is replaced.
   ///
   /// # Errors
   ///
   /// Fails when the path is taken or cannot be written.
   pub fn listen(path: &Path) -> io::Result<(Self, UnixListener)> {
      let address = SocketAddrUnix::new(path)?;
      let socket = socket_with(
         AddressFamily::UNIX,
         SocketType::STREAM,
         SocketFlags::CLOEXEC,
         None,
      )?;

      if bind(&socket, &address) == Err(Errno::ADDRINUSE) {
         let stale = fs::symlink_metadata(path)?.file_type().is_socket()
            && UnixStream::connect(path)
               .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused);

         if !stale {
            return Err(Errno::ADDRINUSE.into());
         }

         fs::remove_file(path)?;
         bind(&socket, &address)?;
      }

      let file = fs::symlink_metadata(path)?;

      let bound = Self {
         path:  path.to_owned(),
         named: (file.dev(), file.ino()),
      };

      // Nobody can connect before the socket listens, so the mode is in
      // place in time without a change of the process's file mode mask.
      fs::set_permissions(path, Permissions::from_mode(0o600))?;
      listen(&socket, UNIX_BACKLOG)?;

      Ok((bound, socket.into()))
   }
}

impl Drop for Bound {
   fn drop(&mut self) {
      let unchanged =
         fs::symlink_metadata(&self.path).is_ok_and(|file| (file.dev(), file.ino()) == self.named);

      if unchanged {
         let _ = fs::remove_file(&self.path);
      }
   }
}

/// Waits on a thread for the socket that the other side of `link` passes
/// as a descriptor. The receiver yields the result once.
///
/// # Errors
///
/// Fails when the process is out of file descriptors.
pub fn handed(link: &OwnedFd, waker: &Arc<Waker>) -> io::Result<Receiver<io::Result<OwnedFd>>> {
   let (result, receiver) = channel();
   let source = link.try_clone()?;
   let notifier = Arc::clone(waker);

   thread::spawn(move || {
      let passed = receive_message(&source, 1).and_then(|message| {
         message
            .and_then(|(_, descriptors)| descriptors.into_iter().next())
            .ok_or_else(|| io::ErrorKind::ConnectionRefused.into())
      });

      let _ = result.send(passed);
      notifier.wake();
   });

   Ok(receiver)
}

/// Largest datagram a relay carries, which is what two length bytes count.
const DATAGRAM_LIMIT: usize = 0xFFFF;
/// How often an idle datagram relay checks whether its stream is gone.
const RELAY_POLL: Timespec = Timespec {
   tv_sec:  1,
   tv_nsec: 0,
};

/// Joins a datagram socket to a byte stream and returns the stream's other
/// end.
///
/// `socket` is a connected UDP socket or one side of a socket pair that
/// keeps message boundaries. Each datagram travels behind two bytes that
/// hold its length.
///
/// # Errors
///
/// Fails when the process is out of file descriptors.
pub fn datagrams(socket: OwnedFd) -> io::Result<OwnedFd> {
   let (mut near, far) = UnixStream::pair()?;
   let mut framed = near.try_clone()?;
   let inbound = socket.try_clone()?;

   let closed = Arc::new(AtomicBool::new(false));
   let gone = Arc::clone(&closed);

   thread::spawn(move || {
      let mut buffer = vec![0; DATAGRAM_LIMIT + 2];

      while !gone.load(Ordering::Relaxed) {
         // The wait ends once a second so that the loop sees `gone`.
         let _ = poll(
            &mut [PollFd::new(&inbound, PollFlags::IN)],
            Some(&RELAY_POLL),
         );

         let count = match recv(&inbound, &mut buffer[2..], RecvFlags::DONTWAIT) {
            Ok((0, _)) => break,
            Ok((count, _)) => count,
            // A refused datagram says nothing about the next one.
            Err(Errno::WOULDBLOCK | Errno::INTR | Errno::CONNREFUSED) => continue,
            Err(_) => break,
         };

         let Ok(length) = u16::try_from(count) else {
            continue;
         };

         buffer[..2].copy_from_slice(&length.to_be_bytes());

         if framed.write_all(&buffer[..count + 2]).is_err() {
            break;
         }
      }
   });

   thread::spawn(move || {
      let mut header = [0; 2];
      let mut buffer = vec![0; DATAGRAM_LIMIT];

      while near.read_exact(&mut header).is_ok() {
         let length = usize::from(u16::from_be_bytes(header));

         if near.read_exact(&mut buffer[..length]).is_err() {
            break;
         }

         // A datagram that is too big for the path is lost alone, as it
         // would be on any network.
         let _ = send(&socket, &buffer[..length], SendFlags::NOSIGNAL);
      }

      closed.store(true, Ordering::Relaxed);
   });

   Ok(far.into())
}

/// Opens a UDP socket to `host:port` on a thread and wraps it with
/// [`datagrams`]. The receiver yields the result once.
fn associate(host: String, port: u16, waker: &Arc<Waker>) -> Receiver<io::Result<OwnedFd>> {
   let (result, receiver) = channel();
   let notifier = Arc::clone(waker);

   thread::spawn(move || {
      let joined = (host.as_str(), port)
         .to_socket_addrs()
         .and_then(|mut found| found.next().ok_or_else(|| io::Error::other("no address")))
         .and_then(|remote| {
            let local = if remote.is_ipv4() {
               SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            } else {
               SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            };

            let socket = UdpSocket::bind(local)?;
            socket.connect(remote)?;

            // This sets the option that forbids fragments, which lets the
            // connection inside find the real path MTU. It also makes the
            // socket non-blocking, which the relay threads do not want.
            UdpSocketState::new((&socket).into())?;
            socket.set_nonblocking(false)?;

            datagrams(socket.into())
         });

      let _ = result.send(joined);
      notifier.wake();
   });

   receiver
}

/// Connects to `host:port` on a thread. The receiver yields the result once.
fn dial(host: String, port: u16, waker: &Arc<Waker>) -> Receiver<io::Result<OwnedFd>> {
   let (result, receiver) = channel();
   let notifier = Arc::clone(waker);

   thread::spawn(move || {
      let connected = TcpStream::connect((host.as_str(), port)).and_then(|stream| {
         stream.set_nodelay(true)?;
         Ok(OwnedFd::from(stream))
      });

      let _ = result.send(connected);
      notifier.wake();
   });

   receiver
}

/// A stream waiting for its socket.
struct Dial {
   /// The stream to join.
   stream:   StreamId,
   /// Yields the connection or the reason it failed.
   pending:  Receiver<io::Result<OwnedFd>>,
   /// Stream data read before the connection existed.
   buffered: Vec<u8>,
   /// Whether that data reached the end of the stream.
   finished: bool,
}

/// Every forwarded connection on one QUIC connection.
#[derive(Default)]
pub struct Forwards {
   /// Streams waiting for a TCP connection.
   dials:  Vec<Dial>,
   /// Streams joined to a socket.
   relays: Vec<Relay>,
}

impl Forwards {
   #[must_use]
   pub const fn len(&self) -> usize {
      self.dials.len() + self.relays.len()
   }

   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.len() == 0
   }

   /// Joins `stream` to a TCP connection to `host:port` once that connects.
   /// `buffered` and `finished` describe data already read from `stream`.
   pub fn dial(
      &mut self,
      stream: StreamId,
      (host, port): (String, u16),
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) {
      self.dials.push(Dial {
         stream,
         pending: dial(host, port, waker),
         buffered,
         finished,
      });
   }

   /// Joins `stream` to a UDP socket that talks to `host:port`, once the name
   /// resolves. `buffered` and `finished` describe data already read from
   /// `stream`.
   pub fn associate(
      &mut self,
      stream: StreamId,
      (host, port): (String, u16),
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) {
      self.dials.push(Dial {
         stream,
         pending: associate(host, port, waker),
         buffered,
         finished,
      });
   }

   /// Joins `stream` to the socket that arrives on `link`, as [`handed`]
   /// describes. `buffered` and `finished` describe data already read from
   /// `stream`.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn handed(
      &mut self,
      stream: StreamId,
      link: &OwnedFd,
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) -> Result<(), Error> {
      self.dials.push(Dial {
         stream,
         pending: handed(link, waker).map_err(Error::Forward)?,
         buffered,
         finished,
      });

      Ok(())
   }

   /// Joins `stream` to an already connected socket.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn attach(
      &mut self,
      stream: StreamId,
      socket: OwnedFd,
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) -> Result<(), Error> {
      self
         .relays
         .push(Relay::socket(stream, socket, waker, buffered, finished)?);
      Ok(())
   }

   /// Joins a stream this side just opened to `socket`, with `opening` as
   /// the stream's first frame.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn open(
      &mut self,
      stream: StreamId,
      opening: &Message,
      socket: OwnedFd,
      waker: &Arc<Waker>,
   ) -> Result<(), Error> {
      let mut relay = Relay::socket(stream, socket, waker, Vec::new(), false)?;
      relay.prefix(opening.encode());

      self.relays.push(relay);
      Ok(())
   }

   /// Moves data on every forward and drops the ones that ended. A forward
   /// whose stream or connection attempt failed is abandoned alone.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn pump(&mut self, connection: &mut Connection, waker: &Arc<Waker>) -> Result<(), Error> {
      for dial in mem::take(&mut self.dials) {
         match dial.pending.try_recv() {
            Ok(Ok(socket)) => {
               self.attach(dial.stream, socket, (dial.buffered, dial.finished), waker)?;
            },
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => Relay::abort(connection, dial.stream),
            Err(TryRecvError::Empty) => self.dials.push(dial),
         }
      }

      self.relays.retain_mut(|relay| {
         if relay.pump(connection).is_err() {
            Relay::abort(connection, relay.stream());
            return false;
         }

         !relay.is_done()
      });

      Ok(())
   }
}
