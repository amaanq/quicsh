//! Moves bytes between one QUIC stream and the [`pipe`](crate::pipe) threads.

use std::{
   collections::VecDeque,
   fs::File,
   os::fd::OwnedFd,
   slice,
   sync::{
      Arc,
      mpsc::{
         Receiver,
         SyncSender,
         TryRecvError,
         TrySendError,
      },
   },
};

use bytes::Bytes;
use quinn_proto::{
   Connection,
   StreamId,
   VarInt,
   WriteError,
};
use rustix::net::{
   Shutdown,
   shutdown,
};

use crate::{
   error::Error,
   pipe::{
      SendHalf,
      Waker,
      reader,
      writer,
   },
   transport::drain,
};

pub struct Relay {
   /// The stream this relay serves.
   stream:    StreamId,
   /// Local input headed for the stream. `None` once the stream is finished.
   outbound:  Option<Receiver<Bytes>>,
   /// A chunk the stream has not fully taken.
   unsent:    Option<Bytes>,
   /// Stream data headed for a local sink. `None` once the sink is closed.
   inbound:   Option<SyncSender<Bytes>>,
   /// Stream data the sink has not taken.
   unwritten: VecDeque<Bytes>,
   /// Whether the peer finished the stream.
   finished:  bool,
   /// Kept so that dropping the relay unblocks the thread reading the socket.
   socket:    Option<OwnedFd>,
}

impl Drop for Relay {
   fn drop(&mut self) {
      if let Some(ref socket) = self.socket {
         let _ = shutdown(socket, Shutdown::Both);
      }
   }
}

impl Relay {
   /// `outbound` and `inbound` are `None` for the directions `stream` lacks.
   /// `buffered` is stream data the caller already read, and `finished` says
   /// that read reached the end of the stream.
   #[must_use]
   pub fn new(
      stream: StreamId,
      outbound: Option<Receiver<Bytes>>,
      inbound: Option<SyncSender<Bytes>>,
      buffered: Vec<u8>,
      finished: bool,
   ) -> Self {
      Self {
         stream,
         outbound,
         unsent: None,
         inbound,
         unwritten: (!buffered.is_empty())
            .then(|| Bytes::from(buffered))
            .into_iter()
            .collect(),
         finished,
         socket: None,
      }
   }

   /// Relays between `stream` and a connected TCP or Unix socket.
   ///
   /// # Errors
   ///
   /// Fails when the process is out of file descriptors.
   pub fn socket(
      stream: StreamId,
      socket: OwnedFd,
      waker: &Arc<Waker>,
      buffered: Vec<u8>,
      finished: bool,
   ) -> Result<Self, Error> {
      let source = File::from(socket.try_clone().map_err(Error::Forward)?);
      let sink = SendHalf(socket.try_clone().map_err(Error::Forward)?);

      let outbound = reader(source, Arc::clone(waker));
      let (inbound, _) = writer(sink, Arc::clone(waker));

      let mut relay = Self::new(stream, Some(outbound), Some(inbound), buffered, finished);
      relay.socket = Some(socket);
      Ok(relay)
   }

   /// Queues `frame` to go out before any local input. Call it once, before
   /// the first [`Relay::pump`].
   pub fn prefix(&mut self, frame: Vec<u8>) {
      self.unsent = Some(frame.into());
   }

   #[must_use]
   pub const fn stream(&self) -> StreamId {
      self.stream
   }

   /// Whether both directions have ended.
   #[must_use]
   pub const fn is_done(&self) -> bool {
      self.outbound.is_none() && self.inbound.is_none()
   }

   /// Abandons the stream in both directions.
   pub fn abort(connection: &mut Connection, stream: StreamId) {
      let _ = connection.send_stream(stream).reset(VarInt::from_u32(1));
      let _ = connection.recv_stream(stream).stop(VarInt::from_u32(1));
   }

   /// Whether local input ended and the stream was finished.
   #[must_use]
   pub const fn sent_all(&self) -> bool {
      self.outbound.is_none()
   }

   /// Whether the peer finished the stream and the sink took every byte.
   #[must_use]
   pub const fn received_all(&self) -> bool {
      self.inbound.is_none()
   }

   /// Ends the outbound direction now and drops local input not yet sent.
   pub fn finish(&mut self, connection: &mut Connection) {
      if self.outbound.take().is_some() {
         let _ = connection.send_stream(self.stream).finish();
      }

      self.unsent = None;
   }

   /// Moves as much as both sides accept right now.
   ///
   /// # Errors
   ///
   /// Fails when the peer reset the stream.
   pub fn pump(&mut self, connection: &mut Connection) -> Result<(), Error> {
      self.send(connection)?;
      self.receive(connection)
   }

   /// Moves local input to the stream.
   fn send(&mut self, connection: &mut Connection) -> Result<(), Error> {
      while let Some(ref outbound) = self.outbound {
         if self.unsent.is_none() {
            match outbound.try_recv() {
               Ok(chunk) => self.unsent = Some(chunk),
               Err(TryRecvError::Empty) => return Ok(()),
               Err(TryRecvError::Disconnected) => {
                  let _ = connection.send_stream(self.stream).finish();
                  self.outbound = None;
                  return Ok(());
               },
            }
         }

         let Some(ref mut chunk) = self.unsent else {
            return Ok(());
         };

         match connection
            .send_stream(self.stream)
            .write_chunks(slice::from_mut(chunk))
         {
            Ok(_) if chunk.is_empty() => self.unsent = None,
            Ok(_) | Err(WriteError::Blocked) => return Ok(()),
            // The peer stopped reading, as when a remote command exits
            // without consuming its input.
            Err(WriteError::Stopped(_)) => {
               self.unsent = None;
               self.outbound = None;
            },
            Err(error @ WriteError::ClosedStream) => return Err(Error::Write(error)),
         }
      }

      Ok(())
   }

   /// Moves stream data to the local sink.
   fn receive(&mut self, connection: &mut Connection) -> Result<(), Error> {
      while let Some(ref inbound) = self.inbound {
         let Some(chunk) = self.unwritten.pop_front() else {
            if self.finished {
               self.inbound = None;
               return Ok(());
            }

            let (chunks, finished) = drain(connection, self.stream)?;
            self.finished = finished;

            if chunks.is_empty() && !finished {
               return Ok(());
            }

            self.unwritten.extend(chunks);
            continue;
         };

         match inbound.try_send(chunk) {
            Ok(()) => {},
            Err(TrySendError::Full(rejected)) => {
               self.unwritten.push_front(rejected);
               return Ok(());
            },
            // The local sink closed, so the peer is told to stop sending.
            Err(TrySendError::Disconnected(_)) => {
               let _ = connection
                  .recv_stream(self.stream)
                  .stop(VarInt::from_u32(0));
               self.unwritten.clear();
               self.inbound = None;
            },
         }
      }

      Ok(())
   }
}
