//! The unprivileged process. It runs QUIC and TLS, parses what clients send
//! and moves session data, and it asks the monitor for anything privileged.

use std::{
   collections::{
      BTreeMap,
      HashMap,
   },
   io,
   net::{
      Ipv4Addr,
      SocketAddr,
   },
   os::{
      fd::AsFd as _,
      unix::net::UnixListener,
   },
   sync::Arc,
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
   report,
};
use quicsh::{
   auth::exporter,
   control::{
      DETACH_LIMIT,
      Deframer,
      Message,
      Outbox,
      Token,
   },
   forward::{
      Acceptor,
      Forwards,
   },
   pipe::Waker,
   relay::Relay,
   tls,
   transport::{
      App,
      Transport,
      Tuning,
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
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
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
   privsep::Helper,
   session::Session,
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
}

impl SigningKey for RemoteKey {
   fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
      offered
         .contains(&SignatureScheme::ED25519)
         .then(|| Box::new(RemoteSigner(self.helper.clone())) as Box<dyn Signer>)
   }

   fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
      Some(SubjectPublicKeyInfoDer::from(self.public.as_slice()))
   }

   fn algorithm(&self) -> SignatureAlgorithm {
      SignatureAlgorithm::ED25519
   }
}

/// Signs through the monitor.
#[derive(Debug)]
struct RemoteSigner(Helper);

impl Signer for RemoteSigner {
   fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
      self
         .0
         .sign(message)
         .map_err(|error| rustls::Error::General(format!("{error}")))
   }

   fn scheme(&self) -> SignatureScheme {
      SignatureScheme::ED25519
   }
}

/// A login the monitor accepted. Dropping it ends the monitor's record of
/// the login and removes the agent socket.
struct Grant {
   /// The number the monitor gave this login.
   id:     u64,
   /// The account that logged in.
   user:   String,
   /// What the client shows to resume this login's sessions.
   token:  Token,
   /// Reaches the monitor.
   helper: Helper,
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
   /// Remote listeners by the client's number for them.
   listeners: BTreeMap<u32, Acceptor>,
   /// Accepts programs that want the client's SSH agent.
   agent:     Option<Acceptor>,
}

/// What is left of a connection that died, until its client returns or the
/// wait runs out.
struct Parked {
   /// The login, which keeps the agent socket in place.
   grant:    Grant,
   /// The terminal sessions that were running.
   sessions: BTreeMap<u32, Session>,
   /// Accepts programs that want the client's SSH agent.
   agent:    Option<Acceptor>,
   /// When the sessions are hung up.
   expires:  Instant,
}

/// State of the network process.
struct Server {
   /// Every connection whose handshake finished.
   peers:  HashMap<ConnectionHandle, Peer>,
   /// Sessions of dead connections by their login's token.
   parked: HashMap<Token, Parked>,
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
               let user = request.user.clone();

               let Some(id) = self.helper.login(request, exporter(connection)?)? else {
                  peer.outbox.push(&Message::Rejected);
                  continue;
               };

               let mut token = Token::default();
               SystemRandom::new()
                  .fill(&mut token)
                  .map_err(|_| report!("system random source failed"))?;

               println!("accepted {label} from {}", origin(connection));
               peer.outbox.push(&Message::Accepted { token });

               peer.grant = Some(Grant {
                  id,
                  user,
                  token,
                  helper: self.helper.clone(),
               });
            },
            Message::Resize { session, size } => {
               if let Some(resized) = peer.sessions.get(&session) {
                  resized.resize(size)?;
               }
            },
            Message::Listen { listener, port } => {
               if peer.grant.is_none() {
                  bail!("forward before login");
               }

               // The listener is reachable from this host only.
               let allowed = (port == 0 || port >= FIRST_UNPRIVILEGED_PORT)
                  && peer.listeners.len() < MAX_LISTENERS
                  && !peer.listeners.contains_key(&listener);

               let bound = allowed
                  .then(|| Acceptor::tcp((Ipv4Addr::LOCALHOST, port).into(), &self.waker).ok())
                  .flatten();

               let reply = match bound {
                  Some((acceptor, chosen)) => {
                     peer.listeners.insert(listener, acceptor);
                     Message::Listening {
                        listener,
                        port: chosen,
                     }
                  },
                  None => Message::Refused { listener },
               };

               peer.outbox.push(&reply);
            },
            _ => bail!("unexpected control message"),
         }
      }

      Ok(())
   }

   /// Sets aside the terminal sessions of a connection that died and drops
   /// the rest of its state.
   fn park(&mut self, now: Instant, handle: ConnectionHandle) {
      let Some(Peer {
         grant: Some(grant),
         mut sessions,
         agent,
         ..
      }) = self.peers.remove(&handle)
      else {
         return;
      };

      sessions.retain(|_, session| session.resumable());

      if sessions.is_empty() {
         return;
      }

      self.parked.insert(grant.token, Parked {
         grant,
         sessions,
         agent,
         expires: now + DETACH_LIMIT,
      });
   }

   /// Gives a parked session to the connection that asked for it on `stream`
   /// and returns whether there was one for this client.
   fn resume(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
      stream: StreamId,
      (token, label, received): (Token, u32, u64),
      pending: (Vec<u8>, bool),
   ) -> Result<bool> {
      // A client can notice a dead path before the server does, and then the
      // old connection still holds the session.
      let stale = self
         .peers
         .iter()
         .find(|&(&other, peer)| {
            other != handle
               && peer
                  .grant
                  .as_ref()
                  .is_some_and(|grant| grant.token == token)
         })
         .map(|(&other, _)| other);

      if let Some(other) = stale {
         self.park(now, other);
      }

      let peer = self
         .peers
         .get_mut(&handle)
         .context("stream on an unknown connection")?;
      let user = &peer.grant.as_ref().context("stream before login")?.user;

      let found = self
         .parked
         .get(&token)
         .is_some_and(|parked| parked.grant.user == *user && parked.sessions.contains_key(&label));

      if !found || peer.sessions.contains_key(&label) {
         return Ok(false);
      }

      let Some(mut parked) = self.parked.remove(&token) else {
         return Ok(false);
      };
      let Some(mut session) = parked.sessions.remove(&label) else {
         return Ok(false);
      };

      session.resume(connection, stream, received, pending)?;
      peer.sessions.insert(label, session);

      // The old login owns the agent socket that the session's environment
      // names, so it replaces the new one.
      peer.grant = Some(parked.grant);
      peer.agent = parked.agent.or_else(|| peer.agent.take());

      Ok(true)
   }

   /// Reads a new client stream until its opening frame is complete, then
   /// starts what the frame asks for.
   fn opening(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
      stream: StreamId,
   ) -> Result<()> {
      let peer = self
         .peers
         .get_mut(&handle)
         .context("stream on an unknown connection")?;
      let grant = peer.grant.as_ref().context("stream before login")?.id;

      let Some(deframer) = peer.opening.get_mut(&stream) else {
         return Ok(());
      };

      let (received, finished) = drain(connection, stream)?;

      for bytes in received {
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
            if peer.sessions.contains_key(&open.session) || peer.sessions.len() >= MAX_SESSIONS {
               bail!("session id reused or too many sessions");
            }

            if open.agent && peer.agent.is_none() {
               let listener = UnixListener::from(self.helper.agent(grant)?);
               peer.agent = Some(Acceptor::unix(listener, &self.waker)?);
            }

            let label = open.session;
            let spawned = self.helper.spawn(grant, open)?;

            let session = Session::adopt(
               label,
               spawned,
               self.helper.clone(),
               stream,
               (buffered, finished),
               connection,
               &self.waker,
            )?;

            peer.sessions.insert(label, session);
         },
         Message::Resume {
            token,
            session,
            received: had,
         } => {
            let wanted = (token, session, had);

            if !self.resume(
               now,
               handle,
               connection,
               stream,
               wanted,
               (buffered, finished),
            )? {
               let _ = connection
                  .send_stream(stream)
                  .write(&Message::Gone.encode());
               let _ = connection.send_stream(stream).finish();
            }
         },
         Message::Connect { host, port } => {
            if peer.forwards.len() >= MAX_FORWARDS {
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
               agent:     None,
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
                  self.opening(now, handle, connection, id)?;
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
               self.opening(now, handle, connection, id)?;
            }
         },
         // A client that closed the connection is done with its sessions, and
         // one that went silent may come back for them.
         Event::ConnectionLost {
            reason: ConnectionError::TimedOut | ConnectionError::Reset,
         } => self.park(now, handle),
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
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      let Some(peer) = self.peers.get_mut(&handle) else {
         return Ok(None);
      };

      let mut finished = Vec::new();

      for (&id, session) in &mut peer.sessions {
         if let Some(status) = session.pump(now, connection)? {
            finished.push((id, status));
         }
      }

      for (session, status) in finished {
         peer.sessions.remove(&session);
         peer.outbox.push(&Message::Exit { session, status });
      }

      if let Some(control) = peer.control {
         peer.outbox.flush(connection, control)?;
      }

      let mut accepted = Vec::new();

      for (&listener, acceptor) in &peer.listeners {
         while let Some(socket) = acceptor.poll() {
            accepted.push((Message::Forwarded { listener }, socket));
         }
      }

      while let Some(socket) = peer.agent.as_ref().and_then(Acceptor::poll) {
         accepted.push((Message::Agent, socket));
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

      let login = peer.grant.is_none().then_some(peer.deadline);
      Ok(peer
         .sessions
         .values()
         .filter_map(Session::deadline)
         .chain(login)
         .min())
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
      let deadline = match self.pump(now, handle, connection) {
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

   fn idle(&mut self, now: Instant) -> Result<Option<Instant>> {
      self.parked.retain(|_, parked| {
         parked.sessions.retain(|_, session| !session.idle(now));
         !parked.sessions.is_empty() && now < parked.expires
      });

      Ok(self.parked.values().map(|parked| parked.expires).min())
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
pub fn run() -> Result<()> {
   set_no_new_privs(true)?;
   set_parent_process_death_signal(Some(Signal::TERM))?;

   let helper = Helper::new(io::stdin().as_fd().try_clone_to_owned()?);
   let (public, listen, socket) = helper.hello()?;

   let crypto = tls::server(Arc::new(RemoteKey {
      helper: helper.clone(),
      public,
   }))?;

   let sockets = helper.clone();
   let opener = Box::new(move |local, remote| {
      sockets
         .socket(local, remote)
         .map_err(|error| io::Error::other(format!("{error}")))
   });

   let mut server = Server {
      peers: HashMap::new(),
      parked: HashMap::new(),
      helper,
      waker: Arc::new(Waker::new()?),
   };

   Transport::adopt(socket, listen, crypto, Tuning::default(), opener)?.run(&mut server)
}
