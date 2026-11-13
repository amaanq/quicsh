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
use rustix::{
   cmsg_space,
   event::{
      EventfdFlags,
      PollFd,
      PollFlags,
      eventfd,
      poll,
   },
   io::{
      read,
      write,
   },
   net::{
      RecvAncillaryBuffer,
      RecvAncillaryMessage,
      RecvFlags,
      SendAncillaryBuffer,
      SendAncillaryMessage,
      SendFlags,
      Shutdown,
      recvmsg,
      sendmsg,
      shutdown,
   },
};

use crate::error::Error;

/// Most bytes one read takes.
const CHUNK: usize = 1 << 16;
/// Chunks a channel holds before its thread waits.
const QUEUE: usize = 16;

/// An eventfd the loop polls beside its sockets.
pub struct Waker(OwnedFd);

impl Waker {
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn new() -> Result<Self, Error> {
      eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
         .map(Self)
         .map_err(|errno| Error::Socket(errno.into()))
   }

   #[expect(
      clippy::host_endian_bytes,
      reason = "the kernel reads an eventfd counter in the host's byte order"
   )]
   pub fn wake(&self) {
      // The only failure is a full counter, which already wakes the loop.
      let _ = write(&self.0, &1_u64.to_ne_bytes());
   }

   pub fn clear(&self) {
      // An empty counter fails with EAGAIN, which means there is nothing to
      // clear.
      let _ = read(&self.0, &mut [0; 8]);
   }
}

impl AsFd for Waker {
   fn as_fd(&self) -> BorrowedFd<'_> {
      self.0.as_fd()
   }
}

/// Sleeps until `descriptor` is ready for `interest`.
fn ready(descriptor: &impl AsFd, interest: PollFlags) {
   let _ = poll(&mut [PollFd::new(descriptor, interest)], None);
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
      let _ = shutdown(&self.0, Shutdown::Write);
   }
}

/// A second handle to the pipe behind `descriptor`, for a pipe whose owner
/// gives out only the number. Borrowing the number itself would need unsafe
/// code.
///
/// # Errors
///
/// Fails when `/proc` is not mounted or the descriptor is closed.
pub fn reopen(descriptor: RawFd) -> io::Result<File> {
   File::open(format!("/proc/self/fd/{descriptor}"))
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

   sendmsg(
      socket,
      &[IoSlice::new(bytes)],
      &mut ancillary,
      SendFlags::NOSIGNAL,
   )?;

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
      RecvFlags::CMSG_CLOEXEC,
   )?;

   if received.bytes == 0 {
      return Ok(None);
   }

   let descriptors = ancillary
      .drain()
      .filter_map(|message| {
         match message {
            RecvAncillaryMessage::ScmRights(descriptors) => Some(descriptors),
            _ => None,
         }
      })
      .flatten()
      .collect();

   bytes.truncate(received.bytes);
   Ok(Some((bytes, descriptors)))
}

/// Writes every chunk sent to it and closes `sink` once the sender is dropped.
/// The handle finishes after the last write.
#[must_use]
pub fn writer<Sink>(mut sink: Sink, waker: Arc<Waker>) -> (SyncSender<Bytes>, JoinHandle<()>)
where
   Sink: Write + AsFd + Send + 'static,
{
   let (sender, chunks) = sync_channel::<Bytes>(QUEUE);

   let handle = thread::spawn(move || {
      'chunks: for chunk in chunks {
         let mut rest = &*chunk;

         while !rest.is_empty() {
            match sink.write(rest) {
               Ok(count @ 1..) => rest = &rest[count..],
               Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
               Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                  ready(&sink, PollFlags::OUT);
               },
               Ok(0) | Err(_) => break 'chunks,
            }
         }

         waker.wake();
      }

      drop(sink);
      waker.wake();
   });

   (sender, handle)
}
