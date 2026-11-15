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
      IoSliceMut,
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
      fd::{
         AsFd as _,
         OwnedFd,
      },
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
   Dir,
   StreamId,
};
use quinn_udp::{
   RecvMeta,
   UdpSocketState,
};
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
};

use crate::{
   control::{
      Deframer,
      Handle,
      Message,
      Outbox,
      Token,
   },
   error::Error,
   pipe::{
      Waker,
      halt,
      receive_message,
      send_message,
   },
   relay::{
      Relay,
      Tail,
   },
   transport::drain,
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
/// Most datagrams the kernel joins into one batch.
const BATCH_LIMIT: usize = 64;
/// Room for a full batch of jumbo frames. The kernel cuts off what does not
/// fit, and 64 datagrams of 1372 bytes are already more than 64 KiB.
const BATCH_BYTES: usize = BATCH_LIMIT * 9216;

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
   let (near, far) = UnixStream::pair()?;
   let mut framed = near.try_clone()?;
   let inbound = socket.try_clone()?;

   let closed = Arc::new(Waker::new().map_err(io::Error::other)?);
   let gone = Arc::clone(&closed);

   thread::spawn(move || {
      let mut buffer = vec![0; DATAGRAM_LIMIT + 2];

      loop {
         let mut watched = [
            PollFd::new(&inbound, PollFlags::IN),
            PollFd::new(&*gone, PollFlags::IN),
         ];
         let _ = poll(&mut watched, None);

         if !watched[1].revents().is_empty() {
            break;
         }

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

      // The other thread holds this socket too, so dropping it here would
      // not end the stream.
      let _ = shutdown(&framed, Shutdown::Write);
   });

   thread::spawn(move || unframe(near, &socket, &closed));

   Ok(far.into())
}

/// Sends each length-prefixed datagram that `framed` yields on `socket`, and
/// wakes `closed` once the stream ends.
fn unframe(mut framed: UnixStream, socket: &OwnedFd, closed: &Waker) {
   let mut header = [0; 2];
   let mut buffer = vec![0; DATAGRAM_LIMIT];

   while framed.read_exact(&mut header).is_ok() {
      let length = usize::from(u16::from_be_bytes(header));

      if framed.read_exact(&mut buffer[..length]).is_err() {
         break;
      }

      // A datagram that is too big for the path is lost alone, as it would
      // be on any network.
      let _ = send(socket, &buffer[..length], SendFlags::NOSIGNAL);
   }

   closed.wake();
}

/// Joins a connected UDP socket to a byte stream as [`datagrams`] does. The
/// kernel may hand over several datagrams of one size as one batch, which
/// costs a busy relay far fewer system calls, and each still gets a frame
/// of its own.
fn batches(socket: UdpSocket) -> io::Result<OwnedFd> {
   // This also forbids fragments, which lets the connection inside find
   // the real path MTU, and makes the socket non-blocking, which the
   // sending thread does not want.
   let state = UdpSocketState::new((&socket).into())?;
   socket.set_nonblocking(false)?;

   let (near, far) = UnixStream::pair()?;
   let mut framed = near.try_clone()?;
   let inbound = socket.try_clone()?;
   let outbound = OwnedFd::from(socket);

   let closed = Arc::new(Waker::new().map_err(io::Error::other)?);
   let gone = Arc::clone(&closed);

   thread::spawn(move || {
      let mut buffer = vec![0; BATCH_BYTES];
      let mut batch = Vec::with_capacity(BATCH_BYTES + 2 * BATCH_LIMIT);

      loop {
         // The socket is only read when that cannot block.
         let mut watched = [
            PollFd::new(&inbound, PollFlags::IN),
            PollFd::new(&*gone, PollFlags::IN),
         ];
         let ready = poll(&mut watched, None);

         if !watched[1].revents().is_empty() {
            break;
         }

         if ready.is_err() || watched[0].revents().is_empty() {
            continue;
         }

         let mut meta = [RecvMeta::default()];
         let received = state.recv(
            (&inbound).into(),
            &mut [IoSliceMut::new(&mut buffer)],
            &mut meta,
         );

         match received {
            Ok(1..) => {},
            // A refused datagram says nothing about the next one.
            Ok(0) => continue,
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(_) => break,
         }

         batch.clear();

         for datagram in buffer[..meta[0].len].chunks(meta[0].stride.max(1)) {
            // One datagram of a batch is never longer than two bytes count.
            let length = u16::try_from(datagram.len()).unwrap_or(u16::MAX);

            batch.extend_from_slice(&length.to_be_bytes());
            batch.extend_from_slice(datagram);
         }

         if framed.write_all(&batch).is_err() {
            break;
         }
      }

      let _ = shutdown(&framed, Shutdown::Write);
   });

   thread::spawn(move || unframe(near, &outbound, &closed));

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

            batches(socket)
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

/// How much more stream data a forward takes before the peer hears of it.
const REPORT_STEP: u64 = 256 << 10;

/// A stream waiting for its socket.
struct Dial {
   /// The stream to join.
   stream:   StreamId,
   /// What names the forward, for one that can outlive its connection.
   kept:     Option<Handle>,
   /// Yields the connection or the reason it failed.
   pending:  Receiver<io::Result<OwnedFd>>,
   /// Stream data read before the connection existed.
   buffered: Vec<u8>,
   /// Whether that data reached the end of the stream.
   finished: bool,
}

/// Where a forward stands with the QUIC connection.
enum Link {
   /// Its stream is open.
   Live,
   /// Its connection died, and it waits to continue on the next one.
   Adrift,
   /// It asked the server to continue and waits for the answer.
   Asking {
      /// The stream of the new connection.
      stream:  StreamId,
      /// What is left to send of the request.
      request: Outbox,
      /// What arrived of the answer.
      answer:  Deframer,
   },
}

/// A stream joined to a socket.
struct Joined {
   /// Moves the data.
   relay:   Relay,
   /// What names the forward, for one that can outlive its connection.
   kept:    Option<Handle>,
   /// The count of taken stream bytes the peer last heard, if it heard.
   told:    Option<u64>,
   /// Where the forward stands with the connection.
   link:    Link,
   /// The frame that opened the stream, for the side that opened it.
   opening: Vec<u8>,
   /// Whether the peer said that it has the forward.
   seen:    bool,
}

impl Joined {
   /// A forward on an open stream. One with a name keeps what it sent until
   /// the peer has it.
   fn live(mut relay: Relay, kept: Option<Handle>) -> Self {
      if kept.is_some() {
         relay.remember(Tail::exact());
      }

      Self {
         relay,
         kept,
         told: None,
         link: Link::Live,
         opening: Vec::new(),
         seen: false,
      }
   }

   /// Reads the server's answer to a request to continue and moves the
   /// relay to the new stream. A forward the server never had starts over
   /// on a stream of its own, since nothing of it was delivered. `false`
   /// means the forward is over.
   fn answered(&mut self, connection: &mut Connection) -> Result<bool, Error> {
      let Link::Asking {
         stream,
         ref mut request,
         ref mut answer,
      } = self.link
      else {
         return Ok(true);
      };

      request.flush(connection, stream)?;

      let (chunks, finished) = drain(connection, stream)?;

      for bytes in chunks {
         answer.push(&bytes);
      }

      let received = match answer.pop()? {
         Some(Message::Resumed { received, .. }) => received,
         Some(_) if self.seen || self.opening.is_empty() => return Ok(false),
         Some(_) => {
            let Some(fresh) = connection.streams().open(Dir::Bi) else {
               return Ok(false);
            };

            let _ = connection.send_stream(stream).finish();

            self.link = Link::Live;
            self.told = None;
            self.relay.resume(
               connection,
               fresh,
               self.opening.clone(),
               0,
               (Vec::new(), false),
            );

            return Ok(true);
         },
         None => return Ok(!finished),
      };

      let Link::Asking { answer: rest, .. } = mem::replace(&mut self.link, Link::Live) else {
         return Ok(true);
      };

      self.told = Some(self.relay.taken());
      self.relay.resume(
         connection,
         stream,
         Vec::new(),
         received,
         (rest.into_rest(), finished),
      );

      Ok(true)
   }
}

/// A forward whose connection died, which the server keeps for a client
/// that shows its token.
pub struct Parked(Joined);

impl Parked {
   /// The secret that continues the forward.
   #[must_use]
   pub fn token(&self) -> Option<Token> {
      self.0.kept.map(|kept| kept.token)
   }

   /// Ends the forward in this process and returns its socket with what
   /// [`Parked::thaw`] needs.
   fn freeze(self) -> Option<(OwnedFd, Vec<u8>)> {
      let kept = self.0.kept?;
      let (socket, relay) = self.0.relay.freeze()?;

      let mut state = kept.label.to_be_bytes().to_vec();
      state.extend_from_slice(&kept.token);
      state.extend_from_slice(&relay);

      Some((socket, state))
   }

   /// The forward that [`Parked::freeze`] ended in another process.
   fn thaw(socket: OwnedFd, state: &[u8], waker: &Arc<Waker>) -> Option<Self> {
      let (label, named) = state.split_first_chunk()?;
      let (token, relay) = named.split_first_chunk()?;

      let mut forward = Joined::live(Relay::thaw(socket, relay, waker)?, None);

      forward.link = Link::Adrift;
      forward.kept = Some(Handle {
         label: u32::from_be_bytes(*label),
         token: *token,
      });

      Some(Self(forward))
   }
}

/// The first message of forwards on their way between two server processes.
/// A process that expects another one takes none of them.
const HANDOVER: &[u8] = b"quicsh forwards 1";
/// Most bytes of a forward's state in one message.
const PIECE: usize = 32 << 10;

/// Ends `forwards` in this process, which is about to exit, and sends them
/// over `link` for [`take_over`]. Each one is a message with its socket and
/// the length of its state, then the state in pieces.
///
/// # Errors
///
/// Fails when `link` does.
pub fn hand_over(link: &OwnedFd, forwards: Vec<Parked>) -> io::Result<()> {
   halt();
   send_message(link, HANDOVER, &[])?;

   for (socket, state) in forwards.into_iter().filter_map(Parked::freeze) {
      let length = u32::try_from(state.len()).map_err(io::Error::other)?;
      send_message(link, &length.to_be_bytes(), &[socket.as_fd()])?;

      for piece in state.chunks(PIECE) {
         send_message(link, piece, &[])?;
      }
   }

   Ok(())
}

/// The forwards that a server process sent with [`hand_over`] before it
/// exited, as many as arrive whole.
///
/// # Errors
///
/// Fails when `link` does.
pub fn take_over(link: &OwnedFd, waker: &Arc<Waker>) -> io::Result<Vec<Parked>> {
   let mut forwards = Vec::new();

   if receive_message(link, PIECE)?.is_none_or(|first| first.0 != HANDOVER) {
      return Ok(forwards);
   }

   while let Some((head, sockets)) = receive_message(link, PIECE)? {
      let length = head
         .first_chunk()
         .and_then(|length| usize::try_from(u32::from_be_bytes(*length)).ok());

      let (Some(socket), Some(wanted)) = (sockets.into_iter().next(), length) else {
         break;
      };

      let mut state = Vec::new();

      while state.len() < wanted {
         let Some((piece, _)) = receive_message(link, PIECE)? else {
            return Ok(forwards);
         };

         state.extend_from_slice(&piece);
      }

      forwards.extend(Parked::thaw(socket, &state, waker));
   }

   Ok(forwards)
}

/// Every forwarded connection on one QUIC connection.
#[derive(Default)]
pub struct Forwards {
   /// Streams waiting for a TCP connection.
   dials:  Vec<Dial>,
   /// Streams joined to a socket.
   joined: Vec<Joined>,
   /// Whether forwards went before sessions on the last turn.
   led:    bool,
}

impl Forwards {
   #[must_use]
   pub const fn len(&self) -> usize {
      self.dials.len() + self.joined.len()
   }

   /// Whether forwards move their data before sessions on this turn. The two
   /// take turns, since whichever writes first can fill the send window.
   pub const fn leads(&mut self) -> bool {
      self.led = !self.led;
      self.led
   }

   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.len() == 0
   }

   /// Joins `stream` to a TCP connection to `host:port` once that connects.
   /// `buffered` and `finished` describe data already read from `stream`.
   pub fn dial(
      &mut self,
      (stream, kept): (StreamId, Handle),
      (host, port): (String, u16),
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) {
      self.dials.push(Dial {
         stream,
         kept: Some(kept),
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
         kept: None,
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
      (stream, kept): (StreamId, Handle),
      link: &OwnedFd,
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) -> Result<(), Error> {
      self.dials.push(Dial {
         stream,
         kept: Some(kept),
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
      (stream, kept): (StreamId, Option<Handle>),
      socket: OwnedFd,
      (buffered, finished): (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) -> Result<(), Error> {
      let relay = Relay::socket(stream, socket, waker, buffered, finished)?;

      self.joined.push(Joined::live(relay, kept));
      Ok(())
   }

   /// Joins a stream this side just opened to `socket`, with `opening` as
   /// the stream's first frame and `kept` as the name that frame gives the
   /// forward, if it gives one.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn open(
      &mut self,
      (stream, kept): (StreamId, Option<Handle>),
      opening: &Message,
      socket: OwnedFd,
      waker: &Arc<Waker>,
   ) -> Result<(), Error> {
      let frame = opening.encode();

      let mut relay = Relay::socket(stream, socket, waker, Vec::new(), false)?;
      relay.prefix(frame.clone());

      let mut forward = Joined::live(relay, kept);
      forward.opening = frame;

      self.joined.push(forward);
      Ok(())
   }

   /// Queues a [`Message::Taken`] for every forward that took enough stream
   /// data since the peer last heard, so that the peer may forget it. The
   /// first one goes out at once and tells the peer that the forward exists.
   pub fn report(&mut self, outbox: &mut Outbox) {
      for forward in &mut self.joined {
         let taken = forward.relay.taken();

         if let Some(kept) = forward.kept
            && matches!(forward.link, Link::Live)
            && forward.told.is_none_or(|told| taken >= told + REPORT_STEP)
         {
            forward.told = Some(taken);
            outbox.push(&Message::Taken {
               session: kept.label,
               taken,
               errors: 0,
            });
         }
      }
   }

   /// Forgets what the forward `label` names sent within its first `taken`
   /// bytes, which the peer has.
   pub fn release(&mut self, label: u32, taken: u64) {
      let named = self
         .joined
         .iter_mut()
         .find(|forward| forward.kept.is_some_and(|kept| kept.label == label));

      if let Some(forward) = named {
         forward.seen = true;
         forward.relay.release(taken);
      }
   }

   /// Cuts every forward loose from a dead connection. The ones without a
   /// name end here, and so do the ones that still waited for a socket.
   pub fn detach(&mut self) {
      self.dials.clear();
      self.joined.retain(|forward| forward.kept.is_some());

      for forward in &mut self.joined {
         forward.link = Link::Adrift;
      }
   }

   /// Asks the server on a new connection for every forward that was cut
   /// loose. One that gets no stream ends.
   pub fn rejoin(&mut self, connection: &mut Connection) {
      self.joined.retain_mut(|forward| {
         let Some(kept) = forward
            .kept
            .filter(|_| matches!(forward.link, Link::Adrift))
         else {
            return true;
         };

         let Some(stream) = connection.streams().open(Dir::Bi) else {
            return false;
         };

         let mut request = Outbox::default();
         request.push(&Message::Resume {
            token:    kept.token,
            session:  kept.label,
            received: forward.relay.taken(),
            errors:   0,
         });

         forward.link = Link::Asking {
            stream,
            request,
            answer: Deframer::default(),
         };

         true
      });
   }

   /// Takes the forwards of a dead connection that a client may continue.
   /// One that this side opened and the client never confirmed ends here,
   /// since a client that does not know it cannot ask for it.
   pub fn park(&mut self) -> Vec<Parked> {
      self.detach();
      self
         .joined
         .retain(|forward| forward.seen || forward.opening.is_empty());

      mem::take(&mut self.joined)
         .into_iter()
         .map(Parked)
         .collect()
   }

   /// Continues `parked` on `stream` for a client that has the first
   /// `received` bytes this side sent. `buffered` and `finished` describe
   /// data already read from `stream`.
   pub fn adopt(
      &mut self,
      Parked(mut forward): Parked,
      connection: &mut Connection,
      stream: StreamId,
      received: u64,
      pending: (Vec<u8>, bool),
   ) {
      let answer = Message::Resumed {
         received: forward.relay.taken(),
         skipped:  0,
      };

      forward.told = Some(forward.relay.taken());
      forward.link = Link::Live;
      forward
         .relay
         .resume(connection, stream, answer.encode(), received, pending);

      self.joined.push(forward);
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
               let pending = (dial.buffered, dial.finished);
               self.attach((dial.stream, dial.kept), socket, pending, waker)?;
            },
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => Relay::abort(connection, dial.stream),
            Err(TryRecvError::Empty) => self.dials.push(dial),
         }
      }

      self.joined.retain_mut(|forward| {
         match forward.link {
            Link::Adrift => return true,
            Link::Asking { stream, .. } => {
               if !forward.answered(connection).unwrap_or(false) {
                  Relay::abort(connection, stream);
                  return false;
               }

               if !matches!(forward.link, Link::Live) {
                  return true;
               }
            },
            Link::Live => {},
         }

         if forward.relay.pump(connection).is_err() {
            Relay::abort(connection, forward.relay.stream());
            return false;
         }

         !forward.relay.is_done()
      });

      if !self.joined.is_empty() {
         self.joined.rotate_left(1);
      }

      Ok(())
   }
}
