//! Listening and dialing for port and agent forwarding.
//!
//! Accepting and connecting block, so each runs on a thread and hands its
//! sockets to the event loop through a channel and a [`Waker`].

use std::{
   io,
   mem,
   net::{
      SocketAddr,
      TcpListener,
      TcpStream,
   },
   os::{
      fd::OwnedFd,
      unix::net::UnixListener,
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
use rustix::net::{
   Shutdown,
   shutdown,
};

use crate::{
   control::Message,
   error::Error,
   pipe::Waker,
   relay::Relay,
};

const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// A listening socket whose accepted connections arrive on a channel.
/// Dropping it stops the listener.
pub struct Acceptor {
   incoming: Receiver<OwnedFd>,
   listener: OwnedFd,
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

   fn spawn(
      listener: OwnedFd,
      mut accept: impl FnMut() -> io::Result<OwnedFd> + Send + 'static,
      waker: &Arc<Waker>,
   ) -> Self {
      let (accepted, incoming) = channel();
      let closed = Arc::new(AtomicBool::new(false));
      let stop = Arc::clone(&closed);
      let waker = Arc::clone(waker);

      thread::spawn(move || {
         while !stop.load(Ordering::Relaxed) {
            match accept() {
               Ok(socket) => {
                  if accepted.send(socket).is_err() {
                     break;
                  }

                  waker.wake();
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

/// Connects to `host:port` on a thread. The receiver yields the result once.
fn dial(host: String, port: u16, waker: &Arc<Waker>) -> Receiver<io::Result<OwnedFd>> {
   let (result, receiver) = channel();
   let waker = Arc::clone(waker);

   thread::spawn(move || {
      let connected = TcpStream::connect((host.as_str(), port)).and_then(|stream| {
         stream.set_nodelay(true)?;
         Ok(OwnedFd::from(stream))
      });

      let _ = result.send(connected);
      waker.wake();
   });

   receiver
}

/// A stream waiting for its TCP connection.
struct Dial {
   stream:   StreamId,
   pending:  Receiver<io::Result<OwnedFd>>,
   buffered: Vec<u8>,
   finished: bool,
}

/// Every forwarded connection on one QUIC connection.
#[derive(Default)]
pub struct Forwards {
   dials:  Vec<Dial>,
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
