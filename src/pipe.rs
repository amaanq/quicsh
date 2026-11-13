//! Blocking file descriptors bridged to the event loop by threads.
//!
//! A terminal or an inherited pipe cannot be switched to non-blocking mode
//! without changing it for every other process that shares it, so a thread
//! per direction does the blocking calls and a [`Waker`] tells the loop when
//! there is something to do.

use std::{
   fs::File,
   io::{
      self,
      Read as _,
      Write,
   },
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
   event::{
      EventfdFlags,
      eventfd,
   },
   io::{
      read,
      write,
   },
   net::{
      Shutdown,
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

/// Reads `source` until it ends. The channel closes at end of input, and a
/// full channel pauses reading.
#[must_use]
pub fn reader(mut source: File, waker: Arc<Waker>) -> Receiver<Bytes> {
   let (chunks, receiver) = sync_channel(QUEUE);

   thread::spawn(move || {
      let mut buffer = vec![0; CHUNK];

      // A terminal whose other side closed fails with EIO, which is its end
      // of input.
      loop {
         let count = match source.read(&mut buffer) {
            Ok(count @ 1..) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(0) | Err(_) => break,
         };

         if chunks
            .send(Bytes::copy_from_slice(&buffer[..count]))
            .is_err()
         {
            break;
         }

         waker.wake();
      }

      drop(chunks);
      waker.wake();
   });

   receiver
}

/// Writes every chunk sent to it and closes `sink` once the sender is dropped.
/// The handle finishes after the last write.
#[must_use]
pub fn writer<Sink>(mut sink: Sink, waker: Arc<Waker>) -> (SyncSender<Bytes>, JoinHandle<()>)
where
   Sink: Write + Send + 'static,
{
   let (sender, chunks) = sync_channel::<Bytes>(QUEUE);

   let handle = thread::spawn(move || {
      for chunk in chunks {
         if sink.write_all(&chunk).is_err() {
            break;
         }

         waker.wake();
      }

      drop(sink);
      waker.wake();
   });

   (sender, handle)
}
