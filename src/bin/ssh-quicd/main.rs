mod agent;
mod child;
mod session;

use std::{
   collections::HashMap,
   fs,
   net::{
      Ipv4Addr,
      SocketAddr,
   },
   path::{
      Path,
      PathBuf,
   },
   process,
   sync::Arc,
   time::{
      Duration,
      Instant,
   },
};

use bytes::Bytes;
use eyre::{
   OptionExt as _,
   Result,
   WrapErr as _,
   bail,
};
use lexopt::{
   Arg,
   Parser,
   ValueExt as _,
};
use quinn_proto::{
   Connection,
   ConnectionHandle,
   Dir,
   Event,
   StreamEvent,
   StreamId,
   VarInt,
};
use rustix::process::geteuid;
use ssh_quic::{
   DEFAULT_PORT,
   auth::{
      Account,
      Request,
      exporter,
   },
   control::{
      Deframer,
      Message,
      Outbox,
   },
   error::Error,
   forward::{
      Acceptor,
      Forwards,
   },
   key::private_from_openssh,
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

use crate::{
   agent::AgentSocket,
   child::Launch,
   session::Session,
};

const LOGIN_GRACE: Duration = Duration::from_secs(120);
const MAX_ATTEMPTS: u32 = 6;
const MAX_SESSIONS: usize = 64;
const MAX_LISTENERS: usize = 16;
const MAX_FORWARDS: usize = 256;
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;
const PROTOCOL_ERROR: VarInt = VarInt::from_u32(1);
const AUTH_FAILED: VarInt = VarInt::from_u32(2);
const USAGE: &str =
   "usage: ssh-quicd [--listen ADDR:PORT] [--host-key FILE] [--authorized-keys FILE]";

enum Mode {
   Serve {
      listen:          SocketAddr,
      host_key:        PathBuf,
      authorized_keys: Option<PathBuf>,
   },
   /// Set by the server when it starts itself for one session.
   Session(Launch),
}

impl Mode {
   fn parse() -> Result<Self> {
      let mut listen = SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT));
      let mut host_key = PathBuf::from("/etc/ssh/ssh_host_ed25519_key");
      let mut authorized_keys = None;
      let mut session = None;
      let mut terminal = None;
      let mut command = None;
      let mut agent = None;

      let mut parser = Parser::from_env();

      while let Some(argument) = parser.next()? {
         match argument {
            Arg::Long("listen") => listen = parser.value()?.parse()?,
            Arg::Long("host-key") => host_key = parser.value()?.into(),
            Arg::Long("authorized-keys") => authorized_keys = Some(parser.value()?.into()),
            Arg::Long("session") => session = Some(parser.value()?.string()?),
            Arg::Long("term") => terminal = Some(parser.value()?.string()?),
            Arg::Long("command") => command = Some(parser.value()?.string()?),
            Arg::Long("agent-socket") => agent = Some(parser.value()?.into()),
            Arg::Long("help") => {
               println!("{USAGE}");
               process::exit(0);
            },
            other => return Err(other.unexpected().into()),
         }
      }

      if let Some(user) = session {
         return Ok(Self::Session(Launch {
            user,
            terminal,
            command,
            agent,
         }));
      }

      Ok(Self::Serve {
         listen,
         host_key,
         authorized_keys,
      })
   }
}

struct Peer {
   control:   Option<StreamId>,
   deframer:  Deframer,
   outbox:    Outbox,
   attempts:  u32,
   account:   Option<Account>,
   deadline:  Instant,
   /// Client streams whose opening frame has not fully arrived.
   opening:   HashMap<StreamId, Deframer>,
   sessions:  HashMap<u32, Session>,
   forwards:  Forwards,
   listeners: HashMap<u32, Acceptor>,
   agent:     Option<AgentSocket>,
}

struct Server {
   peers:           HashMap<ConnectionHandle, Peer>,
   authorized_keys: Option<PathBuf>,
   waker:           Arc<Waker>,
}

/// Returns the account `request` may log in to, if it proves a key that the
/// account accepts.
fn admits(
   request: &Request,
   connection: &Connection,
   authorized_keys: Option<&Path>,
) -> Result<Option<Account>, Error> {
   if request.verify(&exporter(connection)?).is_err() {
      return Ok(None);
   }

   let Some(account) = Account::lookup(&request.user)? else {
      return Ok(None);
   };

   // An unprivileged server cannot switch users, so it serves only its own.
   let server = geteuid();

   if !server.is_root() && server.as_raw() != account.uid {
      return Ok(None);
   }

   Ok(account
      .authorizes(&request.key, authorized_keys)?
      .then_some(account))
}

impl Server {
   fn control(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<()> {
      let peer = self
         .peers
         .get_mut(&handle)
         .ok_or_eyre("data before the handshake finished")?;
      let control = peer
         .control
         .ok_or_eyre("data before the control stream opened")?;

      for bytes in drain(connection, control)?.0 {
         peer.deframer.push(&bytes);
      }

      while let Some(message) = peer.deframer.pop()? {
         match message {
            Message::Request(request) => {
               if peer.account.is_some() {
                  bail!("second login on an authenticated connection");
               }

               peer.attempts += 1;

               if peer.attempts > MAX_ATTEMPTS {
                  connection.close(now, AUTH_FAILED, Bytes::from_static(b"too many attempts"));
                  return Ok(());
               }

               let admitted = admits(&request, connection, self.authorized_keys.as_deref())?;
               let reply = if admitted.is_some() {
                  Message::Accepted
               } else {
                  Message::Rejected
               };
               peer.outbox.push(&reply);

               if admitted.is_some() {
                  println!(
                     "accepted {} for {} from {}",
                     request.key.fingerprint(),
                     request.user,
                     connection.remote_address()
                  );
               }

               peer.account = admitted;
            },
            Message::Resize { session, size } => {
               if let Some(session) = peer.sessions.get(&session) {
                  session.resize(size)?;
               }
            },
            Message::Listen { listener, port } => {
               let account = peer.account.as_ref().ok_or_eyre("forward before login")?;

               // Low ports stay reserved for root, as they are for sshd, and
               // the listener is reachable from this host only.
               let allowed = (port == 0 || port >= FIRST_UNPRIVILEGED_PORT || account.uid == 0)
                  && peer.listeners.len() < MAX_LISTENERS
                  && !peer.listeners.contains_key(&listener);

               let bound = allowed
                  .then(|| Acceptor::tcp((Ipv4Addr::LOCALHOST, port).into(), &self.waker).ok())
                  .flatten();

               let reply = match bound {
                  Some((acceptor, port)) => {
                     peer.listeners.insert(listener, acceptor);
                     Message::Listening { listener, port }
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
         .ok_or_eyre("stream on an unknown connection")?;
      let account = peer.account.as_ref().ok_or_eyre("stream before login")?;

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
               peer.agent = Some(AgentSocket::create(account, &self.waker)?);
            }

            let agent = peer
               .agent
               .as_ref()
               .filter(|_| open.agent)
               .map(AgentSocket::path);

            let session = Session::spawn(
               &open,
               &account.name,
               agent,
               stream,
               (buffered, finished),
               connection,
               &self.waker,
            )?;

            peer.sessions.insert(open.session, session);
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
               account:   None,
               deadline:  now + LOGIN_GRACE,
               opening:   HashMap::new(),
               sessions:  HashMap::new(),
               forwards:  Forwards::default(),
               listeners: HashMap::new(),
               agent:     None,
            });
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
            while let Some(id) = connection.streams().accept(Dir::Bi) {
               let peer = self
                  .peers
                  .get_mut(&handle)
                  .ok_or_eyre("stream before the handshake finished")?;

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
               .ok_or_eyre("data on an unknown connection")?;

            if peer.control == Some(id) {
               self.control(now, handle, connection)?;
            } else {
               self.opening(handle, connection, id)?;
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

      while let Some(socket) = peer.agent.as_ref().and_then(AgentSocket::poll) {
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

      let login = peer.account.is_none().then_some(peer.deadline);
      Ok(peer
         .sessions
         .values()
         .filter_map(Session::deadline)
         .chain(login)
         .min())
   }

   fn drop_peer(&mut self, now: Instant, handle: ConnectionHandle, connection: &mut Connection) {
      connection.close(now, PROTOCOL_ERROR, Bytes::from_static(b"protocol error"));
      self.peers.remove(&handle);
   }
}

impl App for Server {
   type Error = eyre::Report;

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
         eprintln!("closing {}: {error:#}", connection.remote_address());
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
      self.waker.clear();

      let deadline = match self.pump(now, handle, connection) {
         Ok(deadline) => deadline,
         Err(error) => {
            eprintln!("closing {}: {error:#}", connection.remote_address());
            self.drop_peer(now, handle, connection);
            return Ok(None);
         },
      };

      let expired = self
         .peers
         .get(&handle)
         .is_some_and(|peer| peer.account.is_none() && now >= peer.deadline);

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

fn main() -> Result<()> {
   let (listen, host_key, authorized_keys) = match Mode::parse()? {
      Mode::Session(launch) => match launch.run()? {},
      Mode::Serve {
         listen,
         host_key,
         authorized_keys,
      } => (listen, host_key, authorized_keys),
   };

   let key_text = fs::read_to_string(&host_key)
      .wrap_err_with(|| format!("reading host key {}", host_key.display()))?;
   let crypto = tls::server(&private_from_openssh(&key_text)?)?;

   let mut server = Server {
      peers: HashMap::new(),
      authorized_keys,
      waker: Arc::new(Waker::new()?),
   };

   let mut transport = Transport::listen(listen, crypto, Tuning::default())
      .wrap_err_with(|| format!("listening on {listen}"))?;

   println!("listening on udp {listen}");
   transport.run(&mut server)
}
