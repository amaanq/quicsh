//! Blocking file descriptors bridged to the event loop by threads.
//!
//! A terminal or an inherited pipe cannot be switched to non-blocking mode
//! without changing it for every other process that shares it, so a thread
//! per direction does the blocking calls and a [`Waker`] tells the loop when
//! there is something to do.
//!
//! A descriptor may still arrive in non-blocking mode, as the socket pair
//! `rsync` hands its transport does. The threads then wait in `poll`.

use std::{
   fs::File,
   io::{
      self,
      IoSlice,
      IoSliceMut,
      Read as _,
      Write,
   },
   mem::MaybeUninit,
   os::fd::{
      AsFd,
      BorrowedFd,
      OwnedFd,
      RawFd,
   },
   sync::{
      Arc,
      LazyLock,
      atomic::{
         AtomicBool,
         Ordering,
      },
      mpsc::{
         Receiver,
         SyncSender,
         sync_channel,
      },
   },
   thread::{
      self,
      JoinHandle,
   },
};

use bytes::Bytes;
#[cfg(target_os = "linux")]
use rustix::event::{
   EventfdFlags,
   eventfd,
};
use rustix::{
   cmsg_space,
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   io::{
      Errno,
      read,
      write,
   },
   net::{
      AddressFamily,
      RecvAncillaryBuffer,
      RecvAncillaryMessage,
      RecvFlags,
      SendAncillaryBuffer,
      SendAncillaryMessage,
      SendFlags,
      Shutdown,
      SocketFlags,
      SocketType,
      accept_with,
      recv,
      recvmsg,
      send,
      sendmsg,
      shutdown,
      socket_with,
      socketpair,
   },
};
#[cfg(not(target_os = "linux"))]
use rustix::{
   fs::{
      OFlags,
      fcntl_getfl,
      fcntl_setfl,
   },
   io::{
      FdFlags,
      fcntl_setfd,
      ioctl_fionbio,
   },
};

use crate::error::Error;

/// Most bytes one read takes.
const CHUNK: usize = 1 << 16;
/// Chunks a channel holds before its thread waits.
const QUEUE: usize = 16;

/// The send flags that keep a write to a closed peer from raising SIGPIPE.
#[cfg(target_os = "linux")]
pub const NO_SIGNAL: SendFlags = SendFlags::NOSIGNAL;
/// macOS has no `MSG_NOSIGNAL`. The Rust runtime ignores SIGPIPE before
/// `main` runs, which covers the same writes.
#[cfg(not(target_os = "linux"))]
pub const NO_SIGNAL: SendFlags = SendFlags::empty();

/// The receive flags that close passed descriptors on exec.
#[cfg(target_os = "linux")]
const RECEIVE_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;
/// macOS has no `MSG_CMSG_CLOEXEC`, so [`receive_message`] marks them after.
#[cfg(not(target_os = "linux"))]
const RECEIVE_FLAGS: RecvFlags = RecvFlags::empty();

/// A socket that closes on exec.
///
/// # Errors
///
/// Fails when the family or type is not supported or the process is out of
/// file descriptors.
pub fn socket(family: AddressFamily, kind: SocketType) -> io::Result<OwnedFd> {
   #[cfg(target_os = "linux")]
   return Ok(socket_with(family, kind, SocketFlags::CLOEXEC, None)?);

   #[cfg(not(target_os = "linux"))]
   close_on_exec(socket_with(family, kind, SocketFlags::empty(), None)?)
}

/// A connected pair of sockets that close on exec.
///
/// # Errors
///
/// Fails like [`socket`].
pub fn socket_pair(family: AddressFamily, kind: SocketType) -> io::Result<(OwnedFd, OwnedFd)> {
   #[cfg(target_os = "linux")]
   return Ok(socketpair(family, kind, SocketFlags::CLOEXEC, None)?);

   #[cfg(not(target_os = "linux"))]
   {
      let (one, other) = socketpair(family, kind, SocketFlags::empty(), None)?;
      Ok((close_on_exec(one)?, close_on_exec(other)?))
   }
}

/// The next connection on `listener`, closed on exec.
///
/// # Errors
///
/// Fails when the listener does.
pub fn accept(listener: &OwnedFd) -> io::Result<OwnedFd> {
   #[cfg(target_os = "linux")]
   return Ok(accept_with(listener, SocketFlags::CLOEXEC)?);

   #[cfg(not(target_os = "linux"))]
   close_on_exec(accept_with(listener, SocketFlags::empty())?)
}

/// Marks a descriptor close-on-exec after the call that made it, which
/// leaves a window where another thread's child can inherit it.
#[cfg(not(target_os = "linux"))]
fn close_on_exec(descriptor: OwnedFd) -> io::Result<OwnedFd> {
   fcntl_setfd(&descriptor, FdFlags::CLOEXEC)?;
   Ok(descriptor)
}

/// A descriptor the loop polls beside its sockets, an eventfd on Linux and
/// a socket pair elsewhere.
pub struct Waker {
   /// What the loop polls.
   watched: OwnedFd,
   /// The other end of the pair, which [`Waker::wake`] writes to.
   #[cfg(not(target_os = "linux"))]
   poked:   OwnedFd,
}

impl Waker {
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   #[cfg(target_os = "linux")]
   pub fn new() -> Result<Self, Error> {
      eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
         .map(|watched| Self { watched })
         .map_err(|errno| Error::Socket(errno.into()))
   }

   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   #[cfg(not(target_os = "linux"))]
   pub fn new() -> Result<Self, Error> {
      let make = || {
         let (watched, poked) = socket_pair(AddressFamily::UNIX, SocketType::STREAM)?;
         ioctl_fionbio(&watched, true)?;
         ioctl_fionbio(&poked, true)?;
         io::Result::Ok(Self { watched, poked })
      };

      make().map_err(Error::Socket)
   }

   #[cfg(target_os = "linux")]
   #[expect(
      clippy::host_endian_bytes,
      reason = "the kernel reads an eventfd counter in the host's byte order"
   )]
   pub fn wake(&self) {
      // The only failure is a full counter, which already wakes the loop.
      let _ = write(&self.watched, &1_u64.to_ne_bytes());
   }

   #[cfg(not(target_os = "linux"))]
   pub fn wake(&self) {
      // A full socket buffer already wakes the loop.
      let _ = write(&self.poked, &[1]);
   }

   pub fn clear(&self) {
      // An empty counter or socket fails with EAGAIN, which means there is
      // nothing left to clear.
      let mut drained = [0; 64];
      while read(&self.watched, &mut drained).is_ok_and(|length| length == drained.len()) {}
   }
}

impl AsFd for Waker {
   fn as_fd(&self) -> BorrowedFd<'_> {
      self.watched.as_fd()
   }
}

/// Whether [`halt`] ran.
static HALTED: AtomicBool = AtomicBool::new(false);
/// Ends the sleep of a thread that waits for a descriptor once [`halt`] ran.
static HALT: LazyLock<Option<Waker>> = LazyLock::new(|| Waker::new().ok());

/// Stops the threads that read and write descriptors in non-blocking mode,
/// for a process that hands the descriptors to another one.
///
/// A reader stops before its next read. A writer stops once its sink takes
/// no more, and a [`SendHalf`] dropped from here on stays open.
pub fn halt() {
   HALTED.store(true, Ordering::SeqCst);

   if let Some(ref waker) = *HALT {
      waker.wake();
   }
}

/// Sleeps until `descriptor` is ready for `interest` or [`halt`] ran.
fn ready(descriptor: &impl AsFd, interest: PollFlags) {
   let mut watched = vec![PollFd::new(descriptor, interest)];
   watched.extend(HALT.iter().map(|waker| PollFd::new(waker, PollFlags::IN)));

   let _ = poll(&mut watched, None);
}

/// The sending side of a socket. Dropping it tells the peer that no more data
/// follows, while the receiving side stays open.
pub struct SendHalf(pub OwnedFd);

impl Write for SendHalf {
   fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
      Ok(write(&self.0, bytes)?)
   }

   fn flush(&mut self) -> io::Result<()> {
      Ok(())
   }
}

impl AsFd for SendHalf {
   fn as_fd(&self) -> BorrowedFd<'_> {
      self.0.as_fd()
   }
}

impl Drop for SendHalf {
   fn drop(&mut self) {
      if !HALTED.load(Ordering::SeqCst) {
         let _ = shutdown(&self.0, Shutdown::Write);
      }
   }
}

/// A second handle to the pipe behind `descriptor`, for a pipe whose owner
/// gives out only the number. Borrowing the number itself would need unsafe
/// code.
///
/// # Errors
///
/// Fails when `/proc` is not mounted or the descriptor is closed.
#[cfg(target_os = "linux")]
pub fn reopen(descriptor: RawFd) -> io::Result<File> {
   File::open(format!("/proc/self/fd/{descriptor}"))
}

/// A second handle to the pipe behind `descriptor`. macOS opens `/dev/fd`
/// as a duplicate that shares the file status flags, so the pipe turns
/// blocking for its owner too, where Linux opens the pipe afresh.
///
/// # Errors
///
/// Fails when the descriptor is closed.
#[cfg(not(target_os = "linux"))]
pub fn reopen(descriptor: RawFd) -> io::Result<File> {
   let file = File::open(format!("/dev/fd/{descriptor}"))?;
   fcntl_setfl(&file, fcntl_getfl(&file)? - OFlags::NONBLOCK)?;
   Ok(file)
}

/// Turns what a reader read into what it passes on, which may be nothing.
pub type Filter = Box<dyn FnMut(&[u8]) -> Bytes + Send>;

/// Reads `source` until it ends. The channel closes at end of input, and a
/// full channel pauses reading.
#[must_use]
pub fn reader(source: File, waker: Arc<Waker>) -> Receiver<Bytes> {
   spawn_reader(source, None, None, waker)
}

/// Reads like [`reader`] and also ends once `stop` is woken. The thread then
/// leaves `source` alone, as it must when another program reads it next.
/// Everything read goes through `filter` when there is one.
#[must_use]
pub fn reader_until(
   source: File,
   stop: Arc<Waker>,
   filter: Option<Filter>,
   waker: Arc<Waker>,
) -> Receiver<Bytes> {
   spawn_reader(source, Some(stop), filter, waker)
}

/// Starts the thread behind [`reader`] and [`reader_until`].
fn spawn_reader(
   mut source: File,
   stop: Option<Arc<Waker>>,
   mut filter: Option<Filter>,
   waker: Arc<Waker>,
) -> Receiver<Bytes> {
   let (chunks, receiver) = sync_channel(QUEUE);

   thread::spawn(move || {
      let mut buffer = vec![0; CHUNK];

      // A terminal whose other side closed fails with EIO, which is its end
      // of input.
      loop {
         if let Some(ref stopped) = stop {
            let mut fds = [
               PollFd::new(&source, PollFlags::IN),
               PollFd::new(&**stopped, PollFlags::IN),
            ];

            if poll(&mut fds, None).is_ok() && !fds[1].revents().is_empty() {
               break;
            }
         }

         if HALTED.load(Ordering::SeqCst) {
            break;
         }

         let count = match source.read(&mut buffer) {
            Ok(count @ 1..) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
               ready(&source, PollFlags::IN);
               continue;
            },
            Ok(0) | Err(_) => break,
         };

         let read = &buffer[..count];
         let chunk = filter
            .as_mut()
            .map_or_else(|| Bytes::copy_from_slice(read), |change| change(read));

         if chunk.is_empty() {
            continue;
         }

         if chunks.send(chunk).is_err() {
            break;
         }

         waker.wake();
      }

      drop(chunks);
      waker.wake();
   });

   receiver
}

/// Most descriptors one message carries.
const MAX_DESCRIPTORS: usize = 4;

/// Sends one message on a Unix socket, with descriptors for the receiver.
///
/// # Errors
///
/// Fails when the socket does, or with more descriptors than one message
/// carries.
pub fn send_message(
   socket: &OwnedFd,
   bytes: &[u8],
   descriptors: &[BorrowedFd<'_>],
) -> io::Result<()> {
   let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
   let mut ancillary = SendAncillaryBuffer::new(&mut space);

   if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
      return Err(io::Error::other("too many descriptors for one message"));
   }

   sendmsg(socket, &[IoSlice::new(bytes)], &mut ancillary, NO_SIGNAL)?;

   Ok(())
}

/// The next message of at most `limit` bytes and its descriptors, or `None`
/// once the other side is gone.
///
/// # Errors
///
/// Fails when the socket does.
pub fn receive_message(
   socket: &OwnedFd,
   limit: usize,
) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
   let mut bytes = vec![0; limit];
   let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
   let mut ancillary = RecvAncillaryBuffer::new(&mut space);

   let received = recvmsg(
      socket,
      &mut [IoSliceMut::new(&mut bytes)],
      &mut ancillary,
      RECEIVE_FLAGS,
   )?;

   if received.bytes == 0 {
      return Ok(None);
   }

   let descriptors = passed(&mut ancillary)?;

   bytes.truncate(received.bytes);
   Ok(Some((bytes, descriptors)))
}

/// The descriptors that arrived with a message.
fn passed(ancillary: &mut RecvAncillaryBuffer<'_>) -> io::Result<Vec<OwnedFd>> {
   ancillary
      .drain()
      .filter_map(|message| {
         match message {
            RecvAncillaryMessage::ScmRights(descriptors) => Some(descriptors),
            _ => None,
         }
      })
      .flatten()
      .map(|descriptor| {
         #[cfg(not(target_os = "linux"))]
         fcntl_setfd(&descriptor, FdFlags::CLOEXEC)?;
         io::Result::Ok(descriptor)
      })
      .collect()
}

/// Sends one message on a Unix stream socket after its length in four
/// bytes, with descriptors for the receiver. macOS has no `SOCK_SEQPACKET`
/// for [`send_message`].
///
/// # Errors
///
/// Fails like [`send_message`], or with a message over 4 GiB.
pub fn send_framed(
   socket: &OwnedFd,
   bytes: &[u8],
   descriptors: &[BorrowedFd<'_>],
) -> io::Result<()> {
   let length = u32::try_from(bytes.len()).map_err(|_| io::Error::other("message too long"))?;
   let frame = [&length.to_be_bytes()[..], bytes].concat();

   let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
   let mut ancillary = SendAncillaryBuffer::new(&mut space);

   if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
      return Err(io::Error::other("too many descriptors for one message"));
   }

   // The descriptors travel with the first byte, so the rest of a short
   // send goes without them.
   let mut sent = sendmsg(socket, &[IoSlice::new(&frame)], &mut ancillary, NO_SIGNAL)?;

   while sent < frame.len() {
      match send(socket, &frame[sent..], NO_SIGNAL) {
         Ok(more) => sent += more,
         Err(Errno::INTR) => {},
         Err(errno) => return Err(errno.into()),
      }
   }

   Ok(())
}

/// The next message that [`send_framed`] sent, of at most `limit` bytes,
/// and its descriptors, or `None` once the other side is gone.
///
/// # Errors
///
/// Fails when the socket does, the other side leaves in the middle of a
/// message, or the message is longer than `limit`.
pub fn receive_framed(
   socket: &OwnedFd,
   limit: usize,
) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
   let mut length = [0; 4];
   let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
   let mut ancillary = RecvAncillaryBuffer::new(&mut space);

   let received = recvmsg(
      socket,
      &mut [IoSliceMut::new(&mut length)],
      &mut ancillary,
      RECEIVE_FLAGS,
   )?;

   if received.bytes == 0 {
      return Ok(None);
   }

   let descriptors = passed(&mut ancillary)?;
   fill(socket, &mut length[received.bytes..])?;

   let size = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);

   if size > limit {
      return Err(io::Error::other("message too long"));
   }

   let mut bytes = vec![0; size];
   fill(socket, &mut bytes)?;

   Ok(Some((bytes, descriptors)))
}

/// Reads from `socket` until `buffer` is full.
fn fill(socket: &OwnedFd, buffer: &mut [u8]) -> io::Result<()> {
   let mut filled = 0;

   while filled < buffer.len() {
      match recv(socket, &mut buffer[filled..], RecvFlags::empty()) {
         Ok((0, _)) => return Err(io::ErrorKind::UnexpectedEof.into()),
         Ok((length, _)) => filled += length,
         Err(Errno::INTR) => {},
         Err(errno) => return Err(errno.into()),
      }
   }

   Ok(())
}

/// The thread of a [`writer`].
pub struct Writing {
   /// Ends with the bytes the sink is still owed.
   thread: JoinHandle<Vec<u8>>,
   /// Set before the wake that follows the last write.
   done:   Arc<AtomicBool>,
}

impl Writing {
   /// Whether the sink is closed. The thread still counts as running for
   /// a moment after its last wake, so its handle cannot answer this.
   #[must_use]
   pub fn done(&self) -> bool {
      self.done.load(Ordering::SeqCst)
   }

   /// Waits for the last write and returns what a sink that took no more
   /// after [`halt`] is still owed.
   #[must_use]
   pub fn owed(self) -> Vec<u8> {
      self.thread.join().unwrap_or_default()
   }
}

/// Writes every chunk sent to it and closes `sink` once the sender is dropped.
#[must_use]
pub fn writer<Sink>(mut sink: Sink, waker: Arc<Waker>) -> (SyncSender<Bytes>, Writing)
where
   Sink: Write + AsFd + Send + 'static,
{
   let (sender, chunks) = sync_channel::<Bytes>(QUEUE);
   let done = Arc::new(AtomicBool::new(false));
   let closed = Arc::clone(&done);

   let thread = thread::spawn(move || {
      let mut owed = Vec::new();

      'chunks: while let Ok(chunk) = chunks.recv() {
         let mut rest = &*chunk;

         while !rest.is_empty() {
            match sink.write(rest) {
               Ok(count @ 1..) => rest = &rest[count..],
               Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
               Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                  if HALTED.load(Ordering::SeqCst) {
                     owed.extend_from_slice(rest);
                     owed.extend(chunks.try_iter().flatten());
                     break 'chunks;
                  }

                  ready(&sink, PollFlags::OUT);
               },
               Ok(0) | Err(_) => break 'chunks,
            }
         }

         waker.wake();
      }

      drop(sink);
      closed.store(true, Ordering::SeqCst);
      waker.wake();
      owed
   });

   (sender, Writing { thread, done })
}
