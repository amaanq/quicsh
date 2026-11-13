//! The unprivileged process. It runs QUIC and TLS, parses what clients send
//! and moves session data, and it asks the monitor for anything privileged.

use std::{
   collections::{
      BTreeMap,
      HashMap,
   },
   io,
   mem,
   net::{
      Ipv4Addr,
      SocketAddr,
   },
   os::fd::{
      AsFd as _,
      OwnedFd,
   },
   sync::{
      Arc,
      mpsc::{
         Receiver,
         TryRecvError,
      },
   },
   time::{
      Duration,
      Instant,
   },
};

use bytes::Bytes;
use misstep::{
   OptionExt as _,
   Result,
   bail,
};
use quicsh::{
   auth::{
      Forwarding,
      exporter,
   },
   control::{
      Deframer,
      Message,
      Open,
      Outbox,
   },
   forward::{
      Acceptor,
      Forwards,
      handed,
   },
   key::PublicKey,
   pipe::Waker,
   relay::Relay,
   tls,
   transport::{
      App,
      Congestion,
      Transport,
      drain,
   },
};
use quinn_proto::{
   Connection,
   ConnectionError,
   ConnectionHandle,
   Dir,
   Event,
   StreamEvent,
   StreamId,
   VarInt,
};
use rustix::{
   process::{
      Signal,
      set_parent_process_death_signal,
   },
   thread::set_no_new_privs,
};
use rustls::{
   SignatureAlgorithm,
   SignatureScheme,
   pki_types::SubjectPublicKeyInfoDer,
   sign::{
      Signer,
      SigningKey,
   },
};

use crate::{
   privsep::{
      Helper,
      Reply,
   },
   session::{
      Had,
      Session,
   },
};

/// How long a client may take to log in.
const LOGIN_GRACE: Duration = Duration::from_secs(120);
/// Login attempts allowed on one connection.
const MAX_ATTEMPTS: u32 = 6;
/// Sessions allowed on one connection.
const MAX_SESSIONS: usize = 64;
/// Remote listeners allowed on one connection.
const MAX_LISTENERS: usize = 16;
/// Forwarded connections allowed on one connection.
const MAX_FORWARDS: usize = 256;
/// Lowest port a client may ask the server to listen on.
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;
/// Close code for a client that broke the protocol.
const PROTOCOL_ERROR: VarInt = VarInt::from_u32(1);
/// Close code for a client that failed to log in.
const AUTH_FAILED: VarInt = VarInt::from_u32(2);

/// The client's address, with an IPv4 client of the IPv6 socket in IPv4 form.
fn origin(connection: &Connection) -> SocketAddr {
   let address = connection.remote_address();
   SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// A host key that only the monitor can sign with.
#[derive(Debug)]
struct RemoteKey {
   /// Reaches the monitor, which holds the private half.
   helper: Helper,
   /// The public half as a `SubjectPublicKeyInfo` document.
   public: Vec<u8>,
   /// How a key of this type signs.
   scheme: SignatureScheme,
}

impl SigningKey for RemoteKey {
   fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
      offered.contains(&self.scheme).then(|| {
         Box::new(RemoteSigner {
            helper: self.helper.clone(),
            scheme: self.scheme,
         }) as Box<dyn Signer>
      })
   }

   fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
      Some(SubjectPublicKeyInfoDer::from(self.public.as_slice()))
   }

   fn algorithm(&self) -> SignatureAlgorithm {
      if self.scheme == SignatureScheme::ED25519 {
         SignatureAlgorithm::ED25519
      } else {
         SignatureAlgorithm::ECDSA
      }
   }
}

/// Signs through the monitor.
#[derive(Debug)]
struct RemoteSigner {
   /// Reaches the monitor.
   helper: Helper,
   /// How the monitor's key signs.
   scheme: SignatureScheme,
}

impl Signer for RemoteSigner {
   fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
      self
         .helper
         .sign(message)
         .map_err(|error| rustls::Error::General(format!("{error}")))
   }

   fn scheme(&self) -> SignatureScheme {
      self.scheme
   }
}

/// A login the monitor accepted. Dropping it ends the monitor's record of
/// the login.
struct Grant {
   /// The number the monitor gave this login.
   id:         u64,
   /// Which ports the key may forward.
   forwarding: Forwarding,
   /// Reaches the monitor.
   helper:     Helper,
}

impl Drop for Grant {
   fn drop(&mut self) {
      self.helper.logout(self.id);
   }
}

/// State of one client connection.
struct Peer {
   /// The control stream, once the client opened it.
   control:   Option<StreamId>,
   /// Reassembles control messages from the client.
   deframer:  Deframer,
   /// Control messages waiting for send window.
   outbox:    Outbox,
   /// Login attempts so far.
   attempts:  u32,
   /// The accepted login.
   grant:     Option<Grant>,
   /// When an unauthenticated connection is closed.
   deadline:  Instant,
   /// Client streams whose opening frame has not fully arrived.
   opening:   HashMap<StreamId, Deframer>,
   /// Running sessions by the client's number for them.
   sessions:  BTreeMap<u32, Session>,
   /// Every forwarded connection in progress.
   forwards:  Forwards,
   /// Remote listeners by the client's number for them. One on a Unix
   /// socket comes with the link to the process that made it, which
   /// removes the socket's file when the link closes.
   listeners: BTreeMap<u32, (Acceptor, Option<OwnedFd>)>,
   /// Unix sockets that a process is still making for a listener.
   binding:   Vec<Binding>,
}

impl Peer {
   /// Asks for a listener on the Unix socket at `path`, or tells the client
   /// that there will be none.
   fn listen(&mut self, listener: u32, path: String, waker: &Arc<Waker>) -> Result<()> {
      let Some(ref grant) = self.grant else {
         bail!("forward before login");
      };

      let allowed = grant.forwarding.permits_bind()
         && self.listeners.len() + self.binding.len() < MAX_LISTENERS
         && !self.listeners.contains_key(&listener)
         && self.binding.iter().all(|other| other.listener != listener);

      let started = allowed
         .then(|| grant.helper.reach(grant.id, path, true).ok())
         .flatten()
         .and_then(|link| Some((handed(&link, waker).ok()?, link)));

      match started {
         Some((pending, link)) => {
            self.binding.push(Binding {
               listener,
               link,
               pending,
            });
         },
         None => self.outbox.push(&Message::Refused { listener }),
      }

      Ok(())
   }

   /// Joins `stream` to the Unix socket at `path`, which a process of the
   /// account connects to. `pending` is what was already read from `stream`.
   fn reach(
      &mut self,
      connection: &mut Connection,
      stream: StreamId,
      path: String,
      pending: (Vec<u8>, bool),
      waker: &Arc<Waker>,
   ) -> Result<()> {
      let link = self
         .grant
         .as_ref()
         .filter(|login| login.forwarding.permits_reach() && self.forwards.len() < MAX_FORWARDS)
         .and_then(|login| login.helper.reach(login.id, path, false).ok());

      match link {
         Some(socket) => self.forwards.handed(stream, &socket, pending, waker)?,
         None => Relay::abort(connection, stream),
      }

      Ok(())
   }

   /// Starts the listeners whose Unix socket arrived and tells the client
   /// about each, and about each that got none.
   fn bind(&mut self, waker: &Arc<Waker>) {
      for binding in mem::take(&mut self.binding) {
         let listener = binding.listener;

         let made = match binding.pending.try_recv() {
            Err(TryRecvError::Empty) => {
               self.binding.push(binding);
               continue;
            },
            Ok(Ok(socket)) => Acceptor::unix(socket.into(), waker).ok(),
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => None,
         };

         let reply = match made {
            Some(acceptor) => {
               self
                  .listeners
                  .insert(listener, (acceptor, Some(binding.link)));
               Message::Listening { listener, port: 0 }
            },
            None => Message::Refused { listener },
         };

         self.outbox.push(&reply);
      }
   }
}

/// A remote listener on a Unix socket that does not exist yet.
struct Binding {
   /// The client's number for the listener.
   listener: u32,
   /// Reaches the process that makes the socket.
   link:     OwnedFd,
   /// Yields the listening socket or the reason there is none.
   pending:  Receiver<io::Result<OwnedFd>>,
}

/// State of the network process.
struct Server {
   /// Every connection whose handshake finished.
   peers:  HashMap<ConnectionHandle, Peer>,
   /// Reaches the monitor.
   helper: Helper,
   /// Wakes the loop from I/O threads.
   waker:  Arc<Waker>,
}

impl Server {
   /// Handles what arrived on the control stream.
   fn control(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<()> {
      let peer = self
         .peers
         .get_mut(&handle)
         .context("data before the handshake finished")?;
      let control = peer
         .control
         .context("data before the control stream opened")?;

      for bytes in drain(connection, control)?.0 {
         peer.deframer.push(&bytes);
      }

      while let Some(message) = peer.deframer.pop()? {
         match message {
            Message::Request(request) => {
               if peer.grant.is_some() {
                  bail!("second login on an authenticated connection");
               }

               peer.attempts += 1;

               if peer.attempts > MAX_ATTEMPTS {
                  connection.close(now, AUTH_FAILED, Bytes::from_static(b"too many attempts"));
                  return Ok(());
               }

               let label = format!("{} for {}", request.key.fingerprint(), request.user);

               let granted =
                  self
                     .helper
                     .login(request, exporter(connection)?, origin(connection))?;

               let Some(Reply::Granted {
                  grant: id,
                  forwarding,
               }) = granted
               else {
                  peer.outbox.push(&Message::Rejected);
                  continue;
               };

               println!("accepted {label} from {}", origin(connection));
               peer.outbox.push(&Message::Accepted);

               peer.grant = Some(Grant {
                  id,
                  forwarding,
                  helper: self.helper.clone(),
               });
            },
            Message::Resize { session, size } => {
               if let Some(resized) = peer.sessions.get(&session) {
                  resized.resize(size)?;
               }
            },
            Message::Taken {
               session,
               taken,
               errors,
            } => {
               if let Some(confirmed) = peer.sessions.get(&session) {
                  confirmed.release(taken, errors)?;
               }
            },
            Message::Close { session } => {
               if let Some(over) = peer.sessions.remove(&session) {
                  over.close(connection);
               }
            },
            Message::Listen { listener, port } => {
               let Some(ref grant) = peer.grant else {
                  bail!("forward before login");
               };

               // The listener is reachable from this host only.
               let allowed = grant.forwarding.permits_listen(port)
                  && (port == 0 || port >= FIRST_UNPRIVILEGED_PORT)
                  && peer.listeners.len() < MAX_LISTENERS
                  && !peer.listeners.contains_key(&listener);

               let bound = allowed
                  .then(|| Acceptor::tcp((Ipv4Addr::LOCALHOST, port).into(), &self.waker).ok())
                  .flatten();

               let reply = match bound {
                  Some((acceptor, chosen)) => {
                     peer.listeners.insert(listener, (acceptor, None));
                     Message::Listening {
                        listener,
                        port: chosen,
                     }
                  },
                  None => Message::Refused { listener },
               };

               peer.outbox.push(&reply);
            },
            Message::Bind { listener, path } => peer.listen(listener, path, &self.waker)?,
            _ => bail!("unexpected control message"),
         }
      }

      Ok(())
   }

   /// Starts the session a client opened `stream` for, or tells the client
   /// why it did not start.
   fn start(
      helper: &Helper,
      waker: &Arc<Waker>,
      peer: &mut Peer,
      connection: &mut Connection,
      (stream, pending): (StreamId, (Vec<u8>, bool)),
      open: Open,
   ) -> Result<()> {
      let grant = peer.grant.as_ref().context("stream before login")?.id;

      if peer.sessions.contains_key(&open.session) || peer.sessions.len() >= MAX_SESSIONS {
         bail!("session id reused or too many sessions");
      }

      let label = open.session;

      let (token, link) = match helper.spawn(grant, open) {
         Ok(started) => started,
         Err(error) => {
            let reason = format!("{error}");
            peer.outbox.push(&Message::Failed {
               session: label,
               reason,
            });
            let _ = connection.send_stream(stream).finish();
            return Ok(());
         },
      };

      peer.outbox.push(&Message::Resumable {
         session: label,
         token,
      });

      let session = Session::attach(link, label, None, stream, pending, connection, waker)?;
      peer.sessions.insert(label, session);

      Ok(())
   }

   /// Reads a new client stream until its opening frame is complete, then
   /// starts what the frame asks for.
   fn opening(
      &mut self,
      handle: ConnectionHandle,
      connection: &mut Connection,
      stream: StreamId,
   ) -> Result<()> {
      let peer = self
         .peers
         .get_mut(&handle)
         .context("stream on an unknown connection")?;
      let granted = peer.grant.as_ref().context("stream before login")?;
      let grant = granted.id;

      let Some(deframer) = peer.opening.get_mut(&stream) else {
         return Ok(());
      };

      let (chunks, finished) = drain(connection, stream)?;

      for bytes in chunks {
         deframer.push(&bytes);
      }

      let Some(message) = deframer.pop()? else {
         return Ok(());
      };

      let buffered = peer
         .opening
         .remove(&stream)
         .map_or_else(Vec::new, Deframer::into_rest);

      match message {
         Message::Open(open) => {
            let pending = (buffered, finished);
            Self::start(
               &self.helper,
               &self.waker,
               peer,
               connection,
               (stream, pending),
               open,
            )?;
         },
         Message::Resume {
            token,
            session: label,
            received,
            errors,
         } => {
            let link = self
               .helper
               .attach(grant, token)?
               .filter(|_| !peer.sessions.contains_key(&label));

            if let Some(holder) = link {
               let pending = (buffered, finished);
               let session = Session::attach(
                  holder,
                  label,
                  Some(Had { received, errors }),
                  stream,
                  pending,
                  connection,
                  &self.waker,
               )?;

               peer.sessions.insert(label, session);
            } else {
               let _ = connection
                  .send_stream(stream)
                  .write(&Message::Gone.encode());
               let _ = connection.send_stream(stream).finish();
            }
         },
         Message::Associate { host, port } => {
            let permitted = peer
               .grant
               .as_ref()
               .is_some_and(|login| login.forwarding.permits_open(&host, port));

            if !permitted || peer.forwards.len() >= MAX_FORWARDS {
               Relay::abort(connection, stream);
               return Ok(());
            }

            peer
               .forwards
               .associate(stream, (host, port), (buffered, finished), &self.waker);
         },
         Message::Reach { path } => {
            peer.reach(connection, stream, path, (buffered, finished), &self.waker)?;
         },
         Message::Connect { host, port } => {
            let permitted = peer
               .grant
               .as_ref()
               .is_some_and(|login| login.forwarding.permits_open(&host, port));

            if !permitted || peer.forwards.len() >= MAX_FORWARDS {
               Relay::abort(connection, stream);
               return Ok(());
            }

            peer
               .forwards
               .dial(stream, (host, port), (buffered, finished), &self.waker);
         },
         _ => bail!("stream did not start with an opening frame"),
      }

      Ok(())
   }

   /// Handles one connection event, failing on a protocol violation.
   fn handle(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
      event: &Event,
   ) -> Result<()> {
      match *event {
         Event::Connected => {
            self.peers.insert(handle, Peer {
               control:   None,
               deframer:  Deframer::default(),
               outbox:    Outbox::default(),
               attempts:  0,
               grant:     None,
               deadline:  now + LOGIN_GRACE,
               opening:   HashMap::new(),
               sessions:  BTreeMap::new(),
               forwards:  Forwards::default(),
               listeners: BTreeMap::new(),
               binding:   Vec::new(),
            });
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
            while let Some(id) = connection.streams().accept(Dir::Bi) {
               let peer = self
                  .peers
                  .get_mut(&handle)
                  .context("stream before the handshake finished")?;

               if peer.control.is_none() {
                  peer.control = Some(id);
                  self.control(now, handle, connection)?;
               } else {
                  peer.opening.insert(id, Deframer::default());
                  self.opening(handle, connection, id)?;
               }
            }
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
            bail!("clients do not open unidirectional streams");
         },
         Event::Stream(StreamEvent::Readable { id }) => {
            let peer = self
               .peers
               .get(&handle)
               .context("data on an unknown connection")?;

            if peer.control == Some(id) {
               self.control(now, handle, connection)?;
            } else {
               self.opening(handle, connection, id)?;
            }
         },
         // A client that closed the connection is done with its sessions, and
         // one that went silent may come back for them.
         Event::ConnectionLost {
            reason: ConnectionError::TimedOut | ConnectionError::Reset,
         } => {
            if let Some(mut peer) = self.peers.remove(&handle) {
               for session in peer.sessions.values_mut() {
                  session.keep();
               }
            }
         },
         Event::ConnectionLost { .. } => {
            self.peers.remove(&handle);
         },
         _ => {},
      }

      Ok(())
   }

   /// Moves session and forward data and reports finished sessions. Returns
   /// the next instant this connection needs attention.
   fn pump(
      &mut self,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      let Some(peer) = self.peers.get_mut(&handle) else {
         return Ok(None);
      };

      // A session that ended stays until the client closes it or the
      // connection, because its holder goes on only for a client that may
      // still lack the last output.
      for (&session, running) in &mut peer.sessions {
         if let Some(status) = running.pump(connection)? {
            peer.outbox.push(&Message::Exit { session, status });
         }

         if let Some(taken) = running.progress() {
            peer.outbox.push(&Message::Taken {
               session,
               taken,
               errors: 0,
            });
         }
      }

      peer.bind(&self.waker);

      if let Some(control) = peer.control {
         peer.outbox.flush(connection, control)?;
      }

      let mut accepted = Vec::new();

      for (&listener, entry) in &peer.listeners {
         while let Some(socket) = entry.0.poll() {
            accepted.push((Message::Forwarded { listener }, socket));
         }
      }

      for session in peer.sessions.values() {
         while let Some(socket) = session.agent() {
            accepted.push((Message::Agent, socket));
         }
      }

      for (opening, socket) in accepted {
         if peer.forwards.len() >= MAX_FORWARDS {
            break;
         }

         let Some(stream) = connection.streams().open(Dir::Bi) else {
            break;
         };

         peer.forwards.open(stream, &opening, socket, &self.waker)?;
      }

      peer.forwards.pump(connection, &self.waker)?;

      Ok(peer.grant.is_none().then_some(peer.deadline))
   }

   /// Closes a connection and forgets its state.
   fn drop_peer(&mut self, now: Instant, handle: ConnectionHandle, connection: &mut Connection) {
      connection.close(now, PROTOCOL_ERROR, Bytes::from_static(b"protocol error"));
      self.peers.remove(&handle);
   }
}

impl App for Server {
   type Error = misstep::Report;

   fn event(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
      event: Event,
   ) -> Result<()> {
      // One client's protocol violation ends that connection and leaves the
      // server running.
      if let Err(error) = self.handle(now, handle, connection, &event) {
         eprintln!("closing {}: {error}", origin(connection));
         self.drop_peer(now, handle, connection);
      }

      Ok(())
   }

   fn tick(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      let deadline = match self.pump(handle, connection) {
         Ok(deadline) => deadline,
         Err(error) => {
            eprintln!("closing {}: {error}", origin(connection));
            self.drop_peer(now, handle, connection);
            return Ok(None);
         },
      };

      let expired = self
         .peers
         .get(&handle)
         .is_some_and(|peer| peer.grant.is_none() && now >= peer.deadline);

      if expired && !connection.is_closed() {
         connection.close(now, AUTH_FAILED, Bytes::from_static(b"login timed out"));
         self.peers.remove(&handle);
         return Ok(None);
      }

      Ok(deadline)
   }

   fn done(&self) -> bool {
      false
   }

   fn waker(&self) -> Option<&Waker> {
      Some(&self.waker)
   }
}

/// Serves clients on the socket the monitor hands over, and stops with the
/// monitor, since a second server could otherwise share the port with it.
pub fn run(congestion: Congestion) -> Result<()> {
   set_no_new_privs(true)?;
   set_parent_process_death_signal(Some(Signal::TERM))?;

   let helper = Helper::new(io::stdin().as_fd().try_clone_to_owned()?);
   let (
      Reply::Hello {
         key: public,
         listen,
         secret,
      },
      socket,
   ) = helper.hello()?
   else {
      bail!("unexpected reply from the monitor");
   };

   let scheme = tls::scheme(&PublicKey::from_spki(&public)?)?;
   let crypto = tls::server(Arc::new(RemoteKey {
      helper: helper.clone(),
      public,
      scheme,
   }))?;

   let sockets = helper.clone();
   let opener = Box::new(move |local, remote| {
      sockets
         .socket(local, remote)
         .map_err(|error| io::Error::other(format!("{error}")))
   });

   let mut server = Server {
      peers: HashMap::new(),
      helper,
      waker: Arc::new(Waker::new()?),
   };

   Transport::adopt(socket, listen, crypto, congestion, opener, &secret)?.run(&mut server)
}
