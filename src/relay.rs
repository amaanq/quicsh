//! Moves bytes between one QUIC stream and the [`pipe`](crate::pipe) threads.

use std::{
   collections::VecDeque,
   fs::File,
   mem,
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

use bytes::{
   Bytes,
   BytesMut,
};
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

/// Most stream bytes joined into one write to the sink.
const MERGE_LIMIT: usize = 1 << 16;
/// How much sent data a relay keeps for a peer that reconnects.
const TAIL_LIMIT: usize = 256 << 10;

/// The newest bytes sent in one direction, kept so that a peer whose
/// connection died can get the ones it never received.
#[derive(Default)]
pub struct Tail {
   /// The kept bytes, oldest first.
   bytes: VecDeque<u8>,
   /// How many bytes were ever recorded.
   total: u64,
}

impl Tail {
   /// Adds `chunk` and forgets the oldest bytes beyond the limit.
   pub fn record(&mut self, chunk: &[u8]) {
      self.total += chunk.len() as u64;
      self.bytes.extend(chunk);

      let excess = self.bytes.len().saturating_sub(TAIL_LIMIT);
      self.bytes.drain(..excess);
   }

   /// How many of the bytes after the first `received` are no longer kept.
   #[must_use]
   #[expect(
      clippy::missing_const_for_fn,
      reason = "VecDeque::len is const from Rust 1.101, and stable 1.100 rejects it"
   )]
   pub fn dropped(&self, received: u64) -> u64 {
      self
         .total
         .saturating_sub(received)
         .saturating_sub(self.bytes.len() as u64)
   }

   /// The bytes after the first `received`, or as many of them as are kept.
   #[must_use]
   pub fn since(&self, received: u64) -> Vec<u8> {
      let missing = usize::try_from(self.total.saturating_sub(received)).unwrap_or(usize::MAX);
      let start = self.bytes.len().saturating_sub(missing);

      self.bytes.range(start..).copied().collect()
   }
}

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
   /// How many stream bytes this relay has taken.
   taken:     u64,
   /// Local input already sent, for a relay that can resume.
   tail:      Option<Tail>,
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
         taken: buffered.len() as u64,
         tail: None,
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

   /// Starts keeping sent input so that the relay can [`Relay::resume`].
   pub fn remember(&mut self) {
      self.tail = Some(Tail::default());
   }

   /// How many stream bytes the relay has taken, which the peer needs to know
   /// to resume.
   #[must_use]
   pub const fn taken(&self) -> u64 {
      self.taken
   }

   /// Counts stream bytes that the peer could not send again, so that the
   /// count keeps matching the peer's.
   pub const fn skip(&mut self, bytes: u64) {
      self.taken += bytes;
   }

   /// Moves the relay to `stream` on a new connection. `frame` goes out
   /// first, then the input the peer lacks after its first `received` bytes.
   /// `buffered` and `finished` mean what they do in [`Relay::new`].
   pub fn resume(
      &mut self,
      connection: &mut Connection,
      stream: StreamId,
      frame: Vec<u8>,
      received: u64,
      (buffered, finished): (Vec<u8>, bool),
   ) {
      let mut replay = frame;

      if let Some(ref tail) = self.tail {
         replay.extend(tail.since(received));
      }

      self.stream = stream;
      self.unsent = (!replay.is_empty()).then(|| replay.into());
      self.taken += buffered.len() as u64;
      self.finished = finished;

      if !buffered.is_empty() {
         self.unwritten.push_back(buffered.into());
      }

      if self.outbound.is_none() {
         let _ = connection.send_stream(stream).finish();
         self.unsent = None;
      }
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
               Ok(chunk) => {
                  if let Some(ref mut tail) = self.tail {
                     tail.record(&chunk);
                  }

                  self.unsent = Some(chunk);
               },
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
            self.taken += chunks.iter().map(|chunk| chunk.len() as u64).sum::<u64>();

            if chunks.is_empty() && !finished {
               return Ok(());
            }

            // The stream yields about one packet's payload per chunk, and the
            // sink's thread does one write and one wake for each chunk.
            let mut merged = BytesMut::new();

            for chunk in chunks {
               if merged.len() + chunk.len() > MERGE_LIMIT {
                  self.unwritten.push_back(mem::take(&mut merged).freeze());
               }

               merged.extend_from_slice(&chunk);
            }

            if !merged.is_empty() {
               self.unwritten.push_back(merged.freeze());
            }

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

#[cfg(test)]
mod tests {
   use crate::relay::{
      TAIL_LIMIT,
      Tail,
   };

   /// A peer gets the bytes after its count, all that are kept when its
   /// count is older than that, and none when it claims more than was sent.
   #[test]
   fn tail_replays_what_the_peer_lacks() {
      let mut tail = Tail::default();
      tail.record(b"hello ");
      tail.record(b"world");

      assert_eq!(tail.since(6), b"world", "second chunk only");
      assert_eq!(tail.since(11), b"", "peer has everything");
      assert_eq!(tail.since(99), b"", "peer claims too much");

      tail.record(&vec![b'x'; TAIL_LIMIT]);

      assert_eq!(tail.since(0).len(), TAIL_LIMIT, "older bytes are gone");
      assert_eq!(tail.dropped(0), 11, "the first two chunks");
      assert_eq!(tail.dropped(11), 0, "nothing the peer lacks");
      assert_eq!(tail.since(tail.total - 3), b"xxx", "count still lines up");
   }
}
