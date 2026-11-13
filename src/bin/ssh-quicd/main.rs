mod child;
mod session;

use std::{
   collections::HashMap,
   fs,
   net::SocketAddr,
   path::{
      Path,
      PathBuf,
   },
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
   },
   error::Error,
   key::private_from_openssh,
   pipe::Waker,
   tls,
   transport::{
      App,
      Transport,
      Tuning,
      drain,
   },
};

use crate::{
   child::Launch,
   session::Session,
};

const LOGIN_GRACE: Duration = Duration::from_secs(120);
const MAX_ATTEMPTS: u32 = 6;
const MAX_SESSIONS: usize = 64;
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
      let mut listen = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT));
      let mut host_key = PathBuf::from("/etc/ssh/ssh_host_ed25519_key");
      let mut authorized_keys = None;
      let mut session = None;
      let mut terminal = None;
      let mut command = None;

      let mut parser = Parser::from_env();

      while let Some(argument) = parser.next()? {
         match argument {
            Arg::Long("listen") => listen = parser.value()?.parse()?,
            Arg::Long("host-key") => host_key = parser.value()?.into(),
            Arg::Long("authorized-keys") => authorized_keys = Some(parser.value()?.into()),
            Arg::Long("session") => session = Some(parser.value()?.string()?),
            Arg::Long("term") => terminal = Some(parser.value()?.string()?),
            Arg::Long("command") => command = Some(parser.value()?.string()?),
            Arg::Long("help") => {
               println!("{USAGE}");
               std::process::exit(0);
            },
            other => return Err(other.unexpected().into()),
         }
      }

      if let Some(user) = session {
         return Ok(Self::Session(Launch {
            user,
            terminal,
            command,
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
   control:  Option<StreamId>,
   deframer: Deframer,
   attempts: u32,
   user:     Option<String>,
   deadline: Instant,
   /// Session streams whose opening frame has not fully arrived.
   opening:  HashMap<StreamId, Deframer>,
   sessions: HashMap<u32, Session>,
}

struct Server {
   peers:           HashMap<ConnectionHandle, Peer>,
   authorized_keys: Option<PathBuf>,
   waker:           Arc<Waker>,
}

/// Returns whether `request` proves a key that the named account accepts.
fn admits(
   request: &Request,
   connection: &Connection,
   authorized_keys: Option<&Path>,
) -> Result<bool, Error> {
   if request.verify(&exporter(connection)?).is_err() {
      return Ok(false);
   }

   let Some(account) = Account::lookup(&request.user)? else {
      return Ok(false);
   };

   // An unprivileged server cannot switch users, so it serves only its own.
   let server = geteuid();

   if !server.is_root() && server.as_raw() != account.uid {
      return Ok(false);
   }

   account.authorizes(&request.key, authorized_keys)
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
               if peer.user.is_some() {
                  bail!("second login on an authenticated connection");
               }

               peer.attempts += 1;

               if peer.attempts > MAX_ATTEMPTS {
                  connection.close(now, AUTH_FAILED, Bytes::from_static(b"too many attempts"));
                  return Ok(());
               }

               let admitted = admits(&request, connection, self.authorized_keys.as_deref())?;
               let reply = if admitted {
                  Message::Accepted
               } else {
                  Message::Rejected
               };
               connection.send_stream(control).write(&reply.encode())?;

               if admitted {
                  println!(
                     "accepted {} for {} from {}",
                     request.key.fingerprint(),
                     request.user,
                     connection.remote_address()
                  );

                  peer.user = Some(request.user);
               }
            },
            Message::Resize { session, size } => {
               if let Some(session) = peer.sessions.get(&session) {
                  session.resize(size)?;
               }
            },
            _ => bail!("unexpected control message"),
         }
      }

      Ok(())
   }

   /// Reads a new session stream until its opening frame is complete, then
   /// starts the session.
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
      let user = peer.user.as_deref().ok_or_eyre("session before login")?;

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

      let Message::Open(open) = message else {
         bail!("session stream did not start with an open frame");
      };

      if peer.sessions.contains_key(&open.session) || peer.sessions.len() >= MAX_SESSIONS {
         bail!("session id reused or too many sessions");
      }

      let buffered = peer
         .opening
         .remove(&stream)
         .map_or_default(Deframer::into_rest);
      let session = Session::spawn(
         &open,
         user,
         stream,
         (buffered, finished),
         connection,
         &self.waker,
      )?;

      peer.sessions.insert(open.session, session);
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
               control:  None,
               deframer: Deframer::default(),
               attempts: 0,
               user:     None,
               deadline: now + LOGIN_GRACE,
               opening:  HashMap::new(),
               sessions: HashMap::new(),
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

   /// Moves session data and reports finished sessions. Returns the next
   /// instant this connection needs attention.
   fn sessions(
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

         if let Some(control) = peer.control {
            connection
               .send_stream(control)
               .write(&Message::Exit { session, status }.encode())?;
         }
      }

      let login = peer.user.is_none().then_some(peer.deadline);
      Ok(peer
         .sessions
         .values()
         .filter_map(Session::deadline)
         .chain(login)
         .min())
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
         connection.close(now, PROTOCOL_ERROR, Bytes::from_static(b"protocol error"));
         self.peers.remove(&handle);
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

      let deadline = match self.sessions(now, handle, connection) {
         Ok(deadline) => deadline,
         Err(error) => {
            eprintln!("closing {}: {error:#}", connection.remote_address());
            connection.close(now, PROTOCOL_ERROR, Bytes::from_static(b"session error"));
            self.peers.remove(&handle);
            return Ok(None);
         },
      };

      let expired = self
         .peers
         .get(&handle)
         .is_some_and(|peer| peer.user.is_none() && now >= peer.deadline);

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
