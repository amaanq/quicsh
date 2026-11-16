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
         channel,
      },
   },
   thread,
   time::{
      Duration,
      Instant,
   },
};

use bytes::Bytes;
use knell::signals::{
   SignalPipe,
   shutdown_requested,
};
use misstep::{
   OptionExt as _,
   Result,
   bail,
   report,
};
use quicsh::{
   auth::{
      Forwarding,
      exporter,
   },
   control::{
      DETACH_LIMIT,
      Deframer,
      Handle,
      MAX_DIALOGUE,
      Message,
      Open,
      Outbox,
      SERVER_LABEL,
      Size,
      Token,
   },
   forward::{
      Acceptor,
      Forwards,
      Parked,
      hand_over,
      handed,
      take_over,
   },
   key::PublicKey,
   pipe::{
      Waker,
      receive_message,
      send_message,
   },
   relay::{
      Relay,
      following,
   },
   tls,
   transport::{
      App,
      Congestion,
      PROTOCOL_ERROR,
      RECEIVE_WINDOW,
      RESTARTING,
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
   hold::Packet,
   privsep::{
      Helper,
      Reply,
   },
   session::{
      Had,
      Session,
   },
};

/// Most bytes in what a PAM process sends, which is a [`Message::Prompt`]
/// in its frame.
const MAX_QUESTION: usize = MAX_DIALOGUE + 64;
/// How often a login that gets tickets gets a new one, which leaves each
/// with most of its hour when the connection is lost.
const TICKET_REFRESH: Duration = Duration::from_mins(10);
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
/// Most characters of a session's window title in a list of sessions.
const TITLE_LIMIT: usize = 80;
/// Lowest port a client may ask the server to listen on.
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;
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
      match self.scheme {
         SignatureScheme::ED25519 => SignatureAlgorithm::ED25519,
         SignatureScheme::RSA_PSS_SHA256 => SignatureAlgorithm::RSA,
         _ => SignatureAlgorithm::ECDSA,
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
   /// When the client gets its next ticket, for a login that a password
   /// or a ticket started.
   renew:      Option<Instant>,
}

impl Grant {
   /// A line about each terminal session of the account.
   fn list(&self) -> Result<Vec<String>> {
      let names = self.helper.names(self.id)?;
      Ok(names.into_iter().map(|name| self.describe(name)).collect())
   }

   /// One line about the session `name` for a client that lists its
   /// account's sessions. After the name come whether a client is
   /// connected, how long ago the session wrote anything and the window
   /// title, when the session's holder says so.
   fn describe(&self, name: String) -> String {
      let about = self
         .helper
         .find(self.id, name.clone())
         .ok()
         .flatten()
         .and_then(|held| Packet::inspect(&held.link));

      let Some(Packet::About {
         attached,
         quiet,
         title,
      }) = about
      else {
         return name;
      };

      let state = if attached { "attached" } else { "detached" };

      let idle = match quiet {
         ..60 => format!("{quiet}s"),
         60..3600 => format!("{}m", quiet / 60),
         3600..86400 => format!("{}h", quiet / 3600),
         _ => format!("{}d", quiet / 86400),
      };

      // The title is a program's text, and the client prints the line on
      // a terminal.
      let shown = title
         .chars()
         .filter(|symbol| !symbol.is_control())
         .take(TITLE_LIMIT)
         .collect::<String>();

      format!("{name}\t{state}\tidle {idle}\t{shown}")
         .trim_end()
         .to_owned()
   }
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
   /// The session that moves its data first on the next turn.
   turn:      u32,
   /// Every forwarded connection in progress.
   forwards:  Forwards,
   /// How many forwards this side named.
   named:     u32,
   /// Remote listeners by the client's number for them. One on a Unix
   /// socket comes with the link to the process that made it, which
   /// removes the socket's file when the link closes.
   listeners: BTreeMap<u32, (Acceptor, Option<OwnedFd>)>,
   /// Unix sockets that a process is still making for a listener.
   binding:   Vec<Binding>,
   /// The login that PAM is deciding.
   asking:    Option<Conversation>,
}

impl Peer {
   /// Tells the client that its login passed and takes on what it may do.
   fn accept(
      &mut self,
      id: u64,
      forwarding: Forwarding,
      helper: &Helper,
      connection: &mut Connection,
      ticketed: bool,
   ) {
      self.outbox.push(&Message::Accepted);
      connection.set_receive_window(VarInt::from_u32(RECEIVE_WINDOW));

      self.grant = Some(Grant {
         id,
         forwarding,
         helper: helper.clone(),
         renew: ticketed.then(Instant::now),
      });
   }

   /// Logs in a client that shows a ticket, or tells it that the ticket
   /// is no good.
   fn redeem(
      &mut self,
      now: Instant,
      user: &str,
      ticket: &[u8],
      helper: &Helper,
      connection: &mut Connection,
   ) -> Result<()> {
      if self.spent(now, connection)? {
         return Ok(());
      }

      let Some(Reply::Granted { grant, forwarding }) =
         helper.redeem(user, ticket, origin(connection))?
      else {
         self.outbox.push(&Message::Rejected);
         return Ok(());
      };

      println!("accepted a ticket for {user} from {}", origin(connection));
      self.accept(grant, forwarding, helper, connection, true);

      Ok(())
   }

   /// Starts a login that PAM decides, or tells the client that this
   /// server takes no passwords.
   fn ask(
      &mut self,
      now: Instant,
      user: String,
      helper: &Helper,
      waker: &Arc<Waker>,
      connection: &mut Connection,
   ) -> Result<()> {
      if self.spent(now, connection)? {
         return Ok(());
      }

      self.asking = Conversation::start(helper, user, origin(connection), waker)?;

      if self.asking.is_none() {
         self.outbox.push(&Message::Rejected);
      }

      Ok(())
   }

   /// Sends a login that gets tickets its next one when that is due.
   fn renew(&mut self) {
      let Some(ref mut grant) = self.grant else {
         return;
      };

      if grant.renew.is_none_or(|due| Instant::now() < due) {
         return;
      }

      if let Ok(ticket) = grant.helper.ticket(grant.id) {
         self.outbox.push(&Message::Ticket(ticket));
      }

      grant.renew = Some(Instant::now() + TICKET_REFRESH);
   }

   /// Counts a login attempt. `true` means it was one too many and the
   /// connection is closed.
   fn spent(&mut self, now: Instant, connection: &mut Connection) -> Result<bool> {
      if self.grant.is_some() || self.asking.is_some() {
         bail!("login on a connection that is past it or in one");
      }

      self.attempts += 1;

      if self.attempts > MAX_ATTEMPTS {
         connection.close(now, AUTH_FAILED, Bytes::from_static(b"too many attempts"));
      }

      Ok(self.attempts > MAX_ATTEMPTS)
   }

   /// Gives PAM what the client typed at its question.
   fn answer(&self, text: &str) {
      if let Some(ref conversation) = self.asking {
         let _ = send_message(&conversation.link, text.as_bytes(), &[]);
      }
   }

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
      forward: (StreamId, Handle),
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
         Some(socket) => self.forwards.handed(forward, &socket, pending, waker)?,
         None => Relay::abort(connection, forward.0),
      }

      Ok(())
   }

   /// A name for a forwarded connection whose stream this side opens.
   fn name(&mut self) -> Result<Handle> {
      self.named = self.named.wrapping_add(1);

      let mut kept = Handle {
         label: SERVER_LABEL | self.named,
         token: Token::default(),
      };

      SystemRandom::new()
         .fill(&mut kept.token)
         .map_err(|_| report!("system random source failed"))?;

      Ok(kept)
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

/// A login that PAM decides, in a process that asks its questions here.
struct Conversation {
   /// The monitor's number for the process.
   id:     u64,
   /// Who wants to log in.
   user:   String,
   /// Takes the client's answers.
   link:   OwnedFd,
   /// Yields each question, and `None` once the process is done.
   heard:  Receiver<Option<Message>>,
   /// Reaches the monitor.
   helper: Helper,
}

impl Conversation {
   /// Starts the process, which is `None` when the server takes no
   /// passwords.
   fn start(
      helper: &Helper,
      user: String,
      remote: SocketAddr,
      waker: &Arc<Waker>,
   ) -> Result<Option<Self>> {
      let Some((id, link)) = helper.converse(user.clone(), remote)? else {
         return Ok(None);
      };

      let (questions, heard) = channel();

      let conversation = Self {
         id,
         user,
         link,
         heard,
         helper: helper.clone(),
      };

      let source = conversation.link.try_clone()?;
      let notifier = Arc::clone(waker);

      thread::spawn(move || {
         loop {
            let prompt = receive_message(&source, MAX_QUESTION)
               .ok()
               .flatten()
               .and_then(|(frame, _)| Message::decode(frame.get(4..)?).ok())
               .filter(|message| matches!(*message, Message::Prompt { .. }));

            let last = prompt.is_none();
            let dropped = questions.send(prompt).is_err();
            notifier.wake();

            if last || dropped {
               return;
            }
         }
      });

      Ok(Some(conversation))
   }
}

impl Drop for Conversation {
   fn drop(&mut self) {
      let _ = self.helper.conclude(self.id, false);
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
   peers:       HashMap<ConnectionHandle, Peer>,
   /// Reaches the monitor.
   helper:      Helper,
   /// The host certificate, empty without one.
   certificate: Vec<u8>,
   /// Wakes the loop from I/O threads.
   waker:       Arc<Waker>,
   /// Forwarded connections of clients that went silent, each with the
   /// instant it is closed at unless a client continues it.
   parked:      Vec<(Instant, Parked)>,
   /// Whether the process was told to stop.
   stopped:     bool,
}

impl Server {
   /// Keeps the forwards of a client that went silent. The oldest ones end
   /// when there are more than one connection may have.
   fn park(&mut self, now: Instant, forwards: Vec<Parked>) {
      let limit = now + DETACH_LIMIT;

      self
         .parked
         .extend(forwards.into_iter().map(|forward| (limit, forward)));

      let surplus = self.parked.len().saturating_sub(MAX_FORWARDS);
      self.parked.drain(..surplus);
   }

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
               if peer.spent(now, connection)? {
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
               peer.accept(id, forwarding, &self.helper, connection, false);
            },
            Message::Redeem { user, ticket } => {
               peer.redeem(now, &user, &ticket, &self.helper, connection)?;
            },
            Message::Converse { user } => {
               peer.ask(now, user, &self.helper, &self.waker, connection)?;
            },
            Message::Answer(text) => peer.answer(&text),
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
               match peer.sessions.get(&session) {
                  Some(confirmed) => confirmed.release(taken, errors)?,
                  None => peer.forwards.release(session, taken),
               }
            },
            Message::Close { session } => {
               if let Some(mut over) = peer.sessions.remove(&session) {
                  over.leave();
                  over.close(connection);
               }
            },
            Message::Stay { session } => peer.sessions.get_mut(&session).map_or((), Session::stay),
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
            asking @ (Message::Sessions | Message::End(_)) => Self::sessions(peer, asking)?,
            Message::Certify => {
               peer
                  .outbox
                  .push(&Message::HostCertificate(self.certificate.clone()));
            },
            _ => bail!("unexpected control message"),
         }
      }

      self.admit(handle, connection)
   }

   /// Reads the streams a client opened along with its login, once the
   /// login passed.
   fn admit(&mut self, handle: ConnectionHandle, connection: &mut Connection) -> Result<()> {
      let mut waiting = self
         .peers
         .get(&handle)
         .filter(|peer| peer.grant.is_some())
         .map_or_else(Vec::new, |peer| peer.opening.keys().copied().collect());

      waiting.sort_unstable();

      for stream in waiting {
         self.opening(handle, connection, stream)?;
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
      let size = open.terminal.as_ref().map(|terminal| terminal.size);

      let held = match helper.spawn(grant, open, origin(connection), connection.local_ip()) {
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

      let session = Session::attach(held.link, label, None, stream, pending, connection, waker)?;

      // A program that draws the whole screen draws it again for a client
      // that joins, once the size changes and changes back.
      if let (true, Some(wanted)) = (held.old, size) {
         session.resize(Size {
            rows: wanted.rows.saturating_add(1),
            ..wanted
         })?;
         session.resize(wanted)?;
      }

      let (taken, skipped) = session.before();

      peer.outbox.push(&Message::Resumable {
         session: label,
         token: held.token,
         name: held.name,
         taken,
         skipped,
      });

      peer.sessions.insert(label, session);

      Ok(())
   }

   /// Answers a client that asks which terminal sessions its account has, or
   /// that ends one of them.
   fn sessions(peer: &mut Peer, message: Message) -> Result<()> {
      let grant = peer.grant.as_ref().context("message before login")?;

      let answer = match message {
         Message::End(name) => {
            match grant.helper.find(grant.id, name.clone())? {
               Some(held) => {
                  Packet::Hangup.send(&held.link)?;
                  Message::Listing(vec![name])
               },
               None => {
                  Message::Failed {
                     session: 0,
                     reason:  format!("no session is named {name}"),
                  }
               },
            }
         },
         _ => Message::Listing(grant.list()?),
      };

      peer.outbox.push(&answer);
      Ok(())
   }

   /// Continues what `token` names on `stream`, a forward this process
   /// kept or else a session in its holder. `label` is the client's number
   /// for it, `had` is what the client has of it and `pending` is what was
   /// already read from `stream`.
   fn resume(
      &mut self,
      handle: ConnectionHandle,
      connection: &mut Connection,
      stream: StreamId,
      (token, label): (Token, u32),
      had: Had,
      pending: (Vec<u8>, bool),
   ) -> Result<()> {
      let peer = self
         .peers
         .get_mut(&handle)
         .context("stream on an unknown connection")?;
      let grant = peer.grant.as_ref().context("stream before login")?.id;

      let parked = self
         .parked
         .iter()
         .position(|entry| entry.1.token() == Some(token));

      if let Some(index) = parked {
         let forward = self.parked.swap_remove(index).1;

         peer
            .forwards
            .adopt(forward, connection, stream, had.received, pending);
         return Ok(());
      }

      let link = self
         .helper
         .attach(grant, token)?
         .filter(|_| !peer.sessions.contains_key(&label));

      if let Some(holder) = link {
         let session = Session::attach(
            holder,
            label,
            Some(had),
            stream,
            pending,
            connection,
            &self.waker,
         )?;

         peer.sessions.insert(label, session);
         return Ok(());
      }

      let _ = connection
         .send_stream(stream)
         .write(&Message::Gone.encode());
      let _ = connection.send_stream(stream).finish();

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

      // A client may ask for its session along with the login. The stream
      // stays unread until the login passed.
      if peer.grant.is_none() {
         return Ok(());
      }

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
            let had = Had { received, errors };
            let pending = (buffered, finished);

            self.resume(handle, connection, stream, (token, label), had, pending)?;
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
         Message::Reach { path, kept } => {
            let forward = (stream, kept);
            peer.reach(connection, forward, path, (buffered, finished), &self.waker)?;
         },
         Message::Connect { host, port, kept } => {
            let permitted = peer
               .grant
               .as_ref()
               .is_some_and(|login| login.forwarding.permits_open(&host, port));

            if !permitted || peer.forwards.len() >= MAX_FORWARDS {
               Relay::abort(connection, stream);
               return Ok(());
            }

            peer.forwards.dial(
               (stream, kept),
               (host, port),
               (buffered, finished),
               &self.waker,
            );
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
               turn:      0,
               forwards:  Forwards::default(),
               named:     0,
               listeners: BTreeMap::new(),
               binding:   Vec::new(),
               asking:    None,
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

               self.park(now, peer.forwards.park());
            }
         },
         Event::ConnectionLost { .. } => {
            if let Some(mut peer) = self.peers.remove(&handle) {
               peer.sessions.values_mut().for_each(Session::leave);
            }
         },
         _ => {},
      }

      Ok(())
   }

   /// Passes on what PAM asks and tells the client what it decided.
   fn converse(&mut self, handle: ConnectionHandle, connection: &mut Connection) -> Result<()> {
      let Some(peer) = self.peers.get_mut(&handle) else {
         return Ok(());
      };
      let Some(ref conversation) = peer.asking else {
         return Ok(());
      };

      loop {
         match conversation.heard.try_recv() {
            Ok(Some(prompt)) => peer.outbox.push(&prompt),
            Ok(None) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => return Ok(()),
         }
      }

      let granted = conversation.helper.conclude(conversation.id, true)?;

      if granted.is_some() {
         let user = &conversation.user;
         println!("accepted a password for {user} from {}", origin(connection));
      }

      peer.asking = None;

      match granted {
         Some(Reply::Granted { grant, forwarding }) => {
            peer.accept(grant, forwarding, &self.helper, connection, true);
         },
         _ => peer.outbox.push(&Message::Rejected),
      }

      self.admit(handle, connection)
   }

   /// Moves session and forward data and reports finished sessions. Returns
   /// the next instant this connection needs attention.
   fn pump(
      &mut self,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      self.converse(handle, connection)?;

      let Some(peer) = self.peers.get_mut(&handle) else {
         return Ok(None);
      };

      if peer.forwards.leads() {
         peer.forwards.pump(connection, &self.waker)?;
      }

      // A session that ended stays until the client closes it or the
      // connection, because its holder goes on only for a client that may
      // still lack the last output.
      for late in [false, true] {
         for (&session, running) in &mut peer.sessions {
            if (session < peer.turn) != late {
               continue;
            }

            if let Some(ended) = running.pump(connection)? {
               peer.outbox.push(&ended.report(session));
            }

            if let Some(taken) = running.progress() {
               peer.outbox.push(&Message::Taken {
                  session,
                  taken,
                  errors: 0,
               });
            }
         }
      }

      peer.turn = following(&peer.sessions, peer.turn);

      peer.bind(&self.waker);
      peer.renew();
      peer.forwards.report(&mut peer.outbox);

      if let Some(control) = peer.control {
         peer.outbox.flush(connection, control)?;
      }

      let mut accepted = Vec::new();

      for (&listener, entry) in &peer.listeners {
         while let Some(socket) = entry.0.poll() {
            accepted.push((Some(listener), socket));
         }
      }

      for session in peer.sessions.values() {
         while let Some(socket) = session.agent() {
            accepted.push((None, socket));
         }
      }

      for (listener, socket) in accepted {
         if peer.forwards.len() >= MAX_FORWARDS {
            break;
         }

         let Some(stream) = connection.streams().open(Dir::Bi) else {
            break;
         };

         let kept = listener.map(|_| peer.name()).transpose()?;

         let opening = listener.zip(kept).map_or(Message::Agent, |named| {
            Message::Forwarded {
               listener: named.0,
               kept:     named.1,
            }
         });

         peer
            .forwards
            .open((stream, kept), &opening, socket, &self.waker)?;
      }

      peer.forwards.pump(connection, &self.waker)?;

      Ok(peer
         .grant
         .as_ref()
         .map_or(Some(peer.deadline), |grant| grant.renew))
   }

   /// Hands every forwarded connection to a process that keeps it for the
   /// next server, lets the sessions go on in their holders and ends the
   /// loop.
   fn stop(&mut self) {
      self
         .peers
         .values_mut()
         .flat_map(|peer| peer.sessions.values_mut())
         .for_each(Session::keep);

      let mut forwards = mem::take(&mut self.parked)
         .into_iter()
         .map(|entry| entry.1)
         .collect::<Vec<Parked>>();

      forwards.extend(
         self
            .peers
            .values_mut()
            .flat_map(|peer| peer.forwards.park()),
      );

      if !forwards.is_empty() {
         let sent = self
            .helper
            .keeper()
            .and_then(|link| Ok(hand_over(&link, forwards)?));

         if let Err(error) = sent {
            eprintln!("forwarded connections end with this server: {error}");
         }
      }

      self.stopped = true;
   }

   /// Closes a connection and forgets its state.
   fn drop_peer(&mut self, now: Instant, handle: ConnectionHandle, connection: &mut Connection) {
      connection.close(
         now,
         PROTOCOL_ERROR,
         Bytes::from_static(b"unreadable message, qsh may be another version"),
      );
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

   fn idle(&mut self, now: Instant) -> Result<Option<Instant>> {
      if shutdown_requested() {
         self.stop();
      }

      self.parked.retain(|entry| now < entry.0);

      Ok(self.parked.iter().map(|entry| entry.0).min())
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
      self.stopped
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
         certificate,
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
      certificate,
      waker: Arc::new(Waker::new()?),
      parked: Vec::new(),
      stopped: false,
   };

   if let Some(link) = server.helper.kept()? {
      let limit = Instant::now() + DETACH_LIMIT;
      let forwards = take_over(&link, &server.waker)?;

      server
         .parked
         .extend(forwards.into_iter().map(|forward| (limit, forward)));
   }

   let signals = SignalPipe::install()?;
   let mut transport = Transport::adopt(socket, listen, crypto, congestion, opener, &secret)?;
   let ended = transport.run(&mut server);

   if server.stopped {
      transport.close(RESTARTING);
   }

   drop(signals);
   ended
}
