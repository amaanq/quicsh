//! Moves bytes between one QUIC stream and the [`pipe`](crate::pipe) threads.

use std::{
   collections::{
      BTreeMap,
      VecDeque,
   },
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
   Dir,
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
/// How much sent data a relay keeps for a peer that reconnects, when it may
/// forget the rest.
const TAIL_LIMIT: u64 = 256 << 10;

/// The key after `turn`, or the first key once `turn` was the last. Sessions
/// that take turns at going first share the send window, which the first
/// writer can fill.
#[must_use]
pub fn following<Session>(sessions: &BTreeMap<u32, Session>, turn: u32) -> u32 {
   let later = turn
      .checked_add(1)
      .and_then(|next| sessions.range(next..).next());

   later
      .or_else(|| sessions.iter().next())
      .map_or(0, |entry| *entry.0)
}

/// The bytes sent in one direction that the peer may lack, kept so that a
/// peer whose connection died can get them again.
pub struct Tail {
   /// The kept chunks, oldest first.
   chunks: VecDeque<Bytes>,
   /// How many bytes came before the first kept chunk.
   start:  u64,
   /// How many bytes were ever recorded.
   total:  u64,
   /// How many bytes are kept before the oldest chunk is forgotten.
   limit:  u64,
}

impl Default for Tail {
   fn default() -> Self {
      Self {
         limit: TAIL_LIMIT,
         ..Self::exact()
      }
   }
}

impl Tail {
   /// A tail that forgets only what [`Tail::release`] names, for a stream
   /// that must continue without a gap.
   #[must_use]
   pub const fn exact() -> Self {
      Self {
         chunks: VecDeque::new(),
         start:  0,
         total:  0,
         limit:  u64::MAX,
      }
   }

   /// Adds `chunk` and forgets the oldest chunks beyond the limit.
   pub fn record(&mut self, chunk: Bytes) {
      self.total += chunk.len() as u64;
      self.chunks.push_back(chunk);

      while let Some(oldest) = self.chunks.front()
         && self.total - self.start - oldest.len() as u64 >= self.limit
      {
         self.start += oldest.len() as u64;
         self.chunks.pop_front();
      }
   }

   /// Forgets the chunks that lie within the first `received` bytes, which
   /// the peer says it has.
   pub fn release(&mut self, received: u64) {
      while let Some(oldest) = self.chunks.front()
         && self.start + oldest.len() as u64 <= received
      {
         self.start += oldest.len() as u64;
         self.chunks.pop_front();
      }
   }

   /// How many of the bytes after the first `received` are no longer kept.
   #[must_use]
   pub const fn dropped(&self, received: u64) -> u64 {
      self.start.saturating_sub(received)
   }

   /// The bytes after the first `received`, or as many of them as are kept.
   #[must_use]
   pub fn since(&self, received: u64) -> Vec<Bytes> {
      let mut offset = self.start;

      self
         .chunks
         .iter()
         .filter_map(|chunk| {
            let skip = usize::try_from(received.saturating_sub(offset)).unwrap_or(usize::MAX);
            offset += chunk.len() as u64;

            (skip < chunk.len()).then(|| chunk.slice(skip..))
         })
         .collect()
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
      // A relay that ended in order may still have bytes on their way to the
      // socket, which closing the sending side would cut off.
      let how = if self.is_done() {
         Shutdown::Read
      } else {
         Shutdown::Both
      };

      if let Some(ref socket) = self.socket {
         let _ = shutdown(socket, how);
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

   /// Starts keeping sent input in `tail` so that the relay can
   /// [`Relay::resume`].
   pub fn remember(&mut self, tail: Tail) {
      self.tail = Some(tail);
   }

   /// Forgets kept input within the first `received` bytes, which the peer
   /// has.
   pub fn release(&mut self, received: u64) {
      if let Some(ref mut tail) = self.tail {
         tail.release(received);
      }
   }

   /// How many input bytes after the first `received` the relay could not
   /// send again.
   #[must_use]
   pub fn lacks(&self, received: u64) -> u64 {
      self.tail.as_ref().map_or(0, |tail| tail.dropped(received))
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
         for chunk in tail.since(received) {
            replay.extend_from_slice(&chunk);
         }
      }

      self.stream = stream;
      self.unsent = (!replay.is_empty()).then(|| replay.into());
      self.taken += buffered.len() as u64;
      self.finished = finished;

      if !buffered.is_empty() {
         self.unwritten.push_back(buffered.into());
      }

      // A relay that only receives may sit on a stream with no sending side.
      if self.outbound.is_none() && self.unsent.is_none() && stream.dir() == Dir::Bi {
         let _ = connection.send_stream(stream).finish();
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

   /// Moves local input to the stream. Input that ended may still have a
   /// replay to send after [`Relay::resume`], and the stream finishes after
   /// it.
   fn send(&mut self, connection: &mut Connection) -> Result<(), Error> {
      loop {
         if self.unsent.is_none() {
            let Some(ref outbound) = self.outbound else {
               return Ok(());
            };

            match outbound.try_recv() {
               Ok(chunk) => {
                  if let Some(ref mut tail) = self.tail {
                     tail.record(chunk.clone());
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
            Ok(_) if chunk.is_empty() => {
               self.unsent = None;

               if self.outbound.is_none() {
                  let _ = connection.send_stream(self.stream).finish();
               }
            },
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
            let mut pending = chunks.iter().map(Bytes::len).sum::<usize>();
            self.taken += pending as u64;

            if chunks.is_empty() && !finished {
               return Ok(());
            }

            // The stream yields about one packet's payload per chunk, and the
            // sink's thread does one write and one wake for each chunk.
            let mut merged = BytesMut::with_capacity(pending.min(MERGE_LIMIT));

            for chunk in chunks {
               if merged.len() + chunk.len() > MERGE_LIMIT {
                  let full = mem::replace(
                     &mut merged,
                     BytesMut::with_capacity(pending.min(MERGE_LIMIT)),
                  );
                  self.unwritten.push_back(full.freeze());
               }

               pending -= chunk.len();
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
   use bytes::Bytes;

   use crate::relay::{
      TAIL_LIMIT,
      Tail,
   };

   /// The kept bytes after the first `received`, joined.
   fn since(tail: &Tail, received: u64) -> Vec<u8> {
      tail.since(received).concat()
   }

   /// A peer gets the bytes after its count, all that are kept when its
   /// count is older than that, and none when it claims more than was sent.
   #[test]
   fn tail_replays_what_the_peer_lacks() {
      let mut tail = Tail::default();
      tail.record(Bytes::from_static(b"hello "));
      tail.record(Bytes::from_static(b"world"));

      assert_eq!(since(&tail, 6), b"world", "second chunk only");
      assert_eq!(since(&tail, 8), b"rld", "part of a chunk");
      assert_eq!(since(&tail, 11), b"", "peer has everything");
      assert_eq!(since(&tail, 99), b"", "peer claims too much");

      let limit = usize::try_from(TAIL_LIMIT).unwrap();
      tail.record(Bytes::from(vec![b'x'; limit]));

      assert_eq!(since(&tail, 0).len(), limit, "older chunks are gone");
      assert_eq!(tail.dropped(0), 11, "the first two chunks");
      assert_eq!(tail.dropped(11), 0, "nothing the peer lacks");
      assert_eq!(since(&tail, tail.total - 3), b"xxx", "count still lines up");
   }

   /// An exact tail keeps everything until the peer confirms it.
   #[test]
   fn exact_tail_forgets_only_what_was_released() {
      let mut tail = Tail::exact();
      let limit = usize::try_from(TAIL_LIMIT).unwrap();

      tail.record(Bytes::from(vec![b'a'; limit]));
      tail.record(Bytes::from(vec![b'b'; limit]));
      tail.record(Bytes::from_static(b"end"));

      assert_eq!(tail.dropped(0), 0, "nothing is forgotten unasked");

      tail.release(TAIL_LIMIT + 5);

      assert_eq!(tail.dropped(0), TAIL_LIMIT, "the confirmed first chunk");
      assert_eq!(
         tail.dropped(TAIL_LIMIT + 5),
         0,
         "the peer lacks nothing kept"
      );
      assert_eq!(
         since(&tail, TAIL_LIMIT * 2),
         b"end",
         "a partly confirmed chunk stays"
      );
   }
}
