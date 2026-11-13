//! The channel between the privileged monitor and the network process.
//!
//! - The network process parses everything a client sends, so it runs without
//!   privileges and holds no secrets.
//! - Whatever needs root or the host key is a [`Request`] to the monitor. Each
//!   request gets exactly one [`Reply`], which can carry file descriptors.
//! - The monitor treats requests as hostile. A network process that a client
//!   took over can start sessions only for users who logged in through it.

use std::{
   fs::File,
   io::{
      self,
      IoSlice,
      IoSliceMut,
   },
   mem::MaybeUninit,
   net::SocketAddr,
   os::fd::{
      AsFd as _,
      BorrowedFd,
      OwnedFd,
   },
   sync::{
      Arc,
      Mutex,
   },
};

use knell::signals::shutdown_requested;
use misstep::{
   OptionExt as _,
   Result,
   bail,
   report,
};
use quicsh::{
   auth,
   control::{
      Message,
      Open,
      Token,
   },
   error::Error,
   wire::{
      Reader,
      put_string,
   },
};
use rustix::{
   cmsg_space,
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   io::Errno,
   net::{
      RecvAncillaryBuffer,
      RecvAncillaryMessage,
      RecvFlags,
      SendAncillaryBuffer,
      SendAncillaryMessage,
      SendFlags,
      recvmsg,
      sendmsg,
   },
};

/// Largest request or reply.
const MAX_MESSAGE: usize = 128 << 10;
/// Most descriptors one message carries.
const MAX_DESCRIPTORS: usize = 4;

/// Tag of [`Request::Hello`] and [`Reply::Hello`].
const HELLO: u8 = 1;
/// Tag of [`Request::Sign`].
const SIGN: u8 = 2;
/// Tag of [`Request::Socket`].
const SOCKET: u8 = 3;
/// Tag of [`Request::Login`].
const LOGIN: u8 = 4;
/// Tag of [`Request::Agent`].
const AGENT: u8 = 5;
/// Tag of [`Request::Spawn`].
const SPAWN: u8 = 6;
/// Tag of [`Request::Hangup`].
const HANGUP: u8 = 7;
/// Tag of [`Request::Logout`].
const LOGOUT: u8 = 8;
/// Tag of [`Request::Attach`].
const ATTACH: u8 = 9;

/// Tag of [`Reply::Signature`].
const SIGNATURE: u8 = 2;
/// Tag of [`Reply::Granted`].
const GRANTED: u8 = 4;
/// Tag of [`Reply::Denied`].
const DENIED: u8 = 5;
/// Tag of [`Reply::Spawned`].
const SPAWNED: u8 = 6;
/// Tag of [`Reply::Done`].
const DONE: u8 = 7;
/// Tag of [`Reply::Failed`].
const FAILED: u8 = 8;
/// Tag of [`Reply::Held`].
const HELD: u8 = 9;

/// What the network process asks of the monitor.
pub enum Request {
   /// Asks for the host public key and the listening socket.
   Hello,
   /// Asks for a host key signature over a TLS handshake transcript.
   Sign(Vec<u8>),
   /// Asks for the UDP socket of one connection.
   Socket {
      /// Address to bind.
      local:  SocketAddr,
      /// The client's address.
      remote: SocketAddr,
   },
   /// Asks whether a login is valid.
   Login {
      /// What the client sent.
      login:    auth::Request,
      /// The connection's TLS exporter value.
      exporter: [u8; 32],
      /// Where the client is.
      remote:   SocketAddr,
   },
   /// Asks for a listening agent socket that the grant's sessions can reach.
   Agent {
      /// The login the socket is for.
      grant: u64,
   },
   /// Asks for a new session.
   Spawn {
      /// The login the session runs as.
      grant: u64,
      /// What the client asked to run.
      open:  Open,
   },
   /// Asks to hang up a session.
   Hangup {
      /// The session to hang up.
      session: u64,
   },
   /// Ends a login and removes its agent socket.
   Logout {
      /// The login to end.
      grant: u64,
   },
   /// Asks for a connection to the holder of a session that is running.
   Attach {
      /// The login that wants the session.
      grant: u64,
      /// What the client showed for it.
      token: Token,
   },
}

/// The monitor's answer to one request.
pub enum Reply {
   /// Comes with the listening UDP socket.
   Hello {
      /// The host key as a `SubjectPublicKeyInfo` document.
      key:    Vec<u8>,
      /// Address the server listens on.
      listen: SocketAddr,
      /// Key material that stays the same across restarts.
      secret: Vec<u8>,
   },
   /// A host key signature.
   Signature(Vec<u8>),
   /// Stands for a successful login in later requests.
   Granted {
      /// The number that names this login.
      grant:      u64,
      /// Whether the key may forward its agent.
      agent:      bool,
      /// Whether the key may forward ports.
      forwarding: bool,
   },
   /// The login was refused.
   Denied,
   /// Comes with standard input, output and error and a status pipe.
   Spawned {
      /// The number that names this session.
      session: u64,
   },
   /// Comes with a connection to the holder of a terminal session.
   Held {
      /// What a client shows to get the session back.
      token: Token,
   },
   /// Success with nothing to say, or with one descriptor that the request
   /// asked for.
   Done,
   /// The request failed, with the reason.
   Failed(String),
}

/// Appends a 64-bit number.
fn put_u64(out: &mut Vec<u8>, value: u64) {
   put_string(out, &value.to_be_bytes());
}

/// Appends an address in its text form.
fn put_address(out: &mut Vec<u8>, address: SocketAddr) {
   put_string(out, address.to_string().as_bytes());
}

/// Reads a 64-bit number.
fn u64_from(reader: &mut Reader<'_>) -> Result<u64, Error> {
   Ok(u64::from_be_bytes(reader.array()?))
}

/// Reads an address from its text form.
fn address(reader: &mut Reader<'_>) -> Result<SocketAddr, Error> {
   str::from_utf8(reader.string()?)
      .ok()
      .and_then(|text| text.parse().ok())
      .ok_or(Error::Frame)
}

impl Request {
   /// The bytes of one channel message.
   fn encode(self) -> Vec<u8> {
      let mut out = Vec::new();

      match self {
         Self::Hello => out.push(HELLO),
         Self::Sign(message) => {
            out.push(SIGN);
            put_string(&mut out, &message);
         },
         Self::Socket { local, remote } => {
            out.push(SOCKET);
            put_address(&mut out, local);
            put_address(&mut out, remote);
         },
         Self::Login {
            login,
            exporter,
            remote,
         } => {
            out.push(LOGIN);
            put_string(&mut out, &exporter);
            put_address(&mut out, remote);
            out.extend_from_slice(&Message::Request(login).encode());
         },
         Self::Agent { grant } => {
            out.push(AGENT);
            put_u64(&mut out, grant);
         },
         Self::Spawn { grant, open } => {
            out.push(SPAWN);
            put_u64(&mut out, grant);
            out.extend_from_slice(&Message::Open(open).encode());
         },
         Self::Hangup { session } => {
            out.push(HANGUP);
            put_u64(&mut out, session);
         },
         Self::Logout { grant } => {
            out.push(LOGOUT);
            put_u64(&mut out, grant);
         },
         Self::Attach { grant, token } => {
            out.push(ATTACH);
            put_u64(&mut out, grant);
            put_string(&mut out, &token);
         },
      }

      out
   }

   /// Parses one channel message.
   fn decode(bytes: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(bytes);

      let request = match reader.byte()? {
         HELLO => Self::Hello,
         SIGN => Self::Sign(reader.string()?.to_vec()),
         SOCKET => {
            Self::Socket {
               local:  address(&mut reader)?,
               remote: address(&mut reader)?,
            }
         },
         LOGIN => {
            let exporter = reader.array()?;
            let remote = address(&mut reader)?;

            let Message::Request(login) = Message::decode(reader.string()?)? else {
               return Err(Error::Frame);
            };

            Self::Login {
               login,
               exporter,
               remote,
            }
         },
         AGENT => {
            Self::Agent {
               grant: u64_from(&mut reader)?,
            }
         },
         SPAWN => {
            let grant = u64_from(&mut reader)?;

            let Message::Open(open) = Message::decode(reader.string()?)? else {
               return Err(Error::Frame);
            };

            Self::Spawn { grant, open }
         },
         HANGUP => {
            Self::Hangup {
               session: u64_from(&mut reader)?,
            }
         },
         LOGOUT => {
            Self::Logout {
               grant: u64_from(&mut reader)?,
            }
         },
         ATTACH => {
            Self::Attach {
               grant: u64_from(&mut reader)?,
               token: reader.array()?,
            }
         },
         _ => return Err(Error::Frame),
      };

      if reader.is_empty() {
         Ok(request)
      } else {
         Err(Error::Frame)
      }
   }
}

impl Reply {
   /// The bytes of one channel message.
   fn encode(&self) -> Vec<u8> {
      let mut out = Vec::new();

      match *self {
         Self::Hello {
            ref key,
            listen,
            ref secret,
         } => {
            out.push(HELLO);
            put_string(&mut out, key);
            put_address(&mut out, listen);
            put_string(&mut out, secret);
         },
         Self::Signature(ref signature) => {
            out.push(SIGNATURE);
            put_string(&mut out, signature);
         },
         Self::Granted {
            grant,
            agent,
            forwarding,
         } => {
            out.push(GRANTED);
            put_u64(&mut out, grant);
            out.extend_from_slice(&[u8::from(agent), u8::from(forwarding)]);
         },
         Self::Denied => out.push(DENIED),
         Self::Spawned { session } => {
            out.push(SPAWNED);
            put_u64(&mut out, session);
         },
         Self::Held { ref token } => {
            out.push(HELD);
            put_string(&mut out, token);
         },
         Self::Done => out.push(DONE),
         Self::Failed(ref text) => {
            out.push(FAILED);
            put_string(&mut out, text.as_bytes());
         },
      }

      out
   }

   /// Parses one channel message.
   fn decode(bytes: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(bytes);

      Ok(match reader.byte()? {
         HELLO => {
            Self::Hello {
               key:    reader.string()?.to_vec(),
               listen: address(&mut reader)?,
               secret: reader.string()?.to_vec(),
            }
         },
         SIGNATURE => Self::Signature(reader.string()?.to_vec()),
         GRANTED => {
            Self::Granted {
               grant:      u64_from(&mut reader)?,
               agent:      reader.byte()? != 0,
               forwarding: reader.byte()? != 0,
            }
         },
         DENIED => Self::Denied,
         SPAWNED => {
            Self::Spawned {
               session: u64_from(&mut reader)?,
            }
         },
         HELD => {
            Self::Held {
               token: reader.array()?,
            }
         },
         DONE => Self::Done,
         FAILED => Self::Failed(String::from_utf8_lossy(reader.string()?).into_owned()),
         _ => return Err(Error::Frame),
      })
   }
}

/// Sends one message with its descriptors.
fn send(channel: &OwnedFd, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) -> io::Result<()> {
   let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
   let mut ancillary = SendAncillaryBuffer::new(&mut space);

   if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors)) {
      return Err(io::Error::other("too many descriptors for one message"));
   }

   sendmsg(
      channel,
      &[IoSlice::new(bytes)],
      &mut ancillary,
      SendFlags::NOSIGNAL,
   )?;

   Ok(())
}

/// The next message, or `None` once the other process is gone.
fn receive(channel: &OwnedFd) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
   let mut bytes = vec![0; MAX_MESSAGE];
   let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(MAX_DESCRIPTORS))];
   let mut ancillary = RecvAncillaryBuffer::new(&mut space);

   let received = recvmsg(
      channel,
      &mut [IoSliceMut::new(&mut bytes)],
      &mut ancillary,
      RecvFlags::CMSG_CLOEXEC,
   )?;

   if received.bytes == 0 {
      return Ok(None);
   }

   let descriptors = ancillary
      .drain()
      .filter_map(|message| {
         match message {
            RecvAncillaryMessage::ScmRights(descriptors) => Some(descriptors),
            _ => None,
         }
      })
      .flatten()
      .collect();

   bytes.truncate(received.bytes);
   Ok(Some((bytes, descriptors)))
}

/// Why [`serve`] returned.
pub enum Ended {
   /// The monitor was told to stop with `SIGINT` or `SIGTERM`.
   Signal,
   /// The network process went away.
   Closed,
}

/// Answers requests with `handle` until the network process goes away or
/// `signal` reports a shutdown signal. A request that fails is reported to
/// the network process and serving goes on.
pub fn serve<Handler>(channel: &OwnedFd, signal: &File, mut handle: Handler) -> Result<Ended>
where
   Handler: FnMut(Request) -> Result<(Reply, Vec<OwnedFd>)>,
{
   loop {
      let mut watched = [
         PollFd::new(channel, PollFlags::IN),
         PollFd::new(signal, PollFlags::IN),
      ];

      match poll(&mut watched, None) {
         Ok(_) | Err(Errno::INTR) => {},
         Err(errno) => return Err(errno.into()),
      }

      if shutdown_requested() {
         return Ok(Ended::Signal);
      }

      if watched[0].revents().is_empty() {
         continue;
      }

      let Some((bytes, _)) = receive(channel)? else {
         return Ok(Ended::Closed);
      };

      let (reply, descriptors) = Request::decode(&bytes)
         .map_err(Into::into)
         .and_then(&mut handle)
         .unwrap_or_else(|error| (Reply::Failed(format!("{error}")), Vec::new()));

      let borrowed = descriptors
         .iter()
         .map(OwnedFd::as_fd)
         .collect::<Vec<BorrowedFd>>();
      send(channel, &reply.encode(), &borrowed)?;
   }
}

/// What the monitor returns for a session on pipes.
pub struct Spawned {
   /// The number that names the session.
   pub session:     u64,
   /// Standard input, output and error, followed by the status pipe.
   pub descriptors: Vec<OwnedFd>,
}

/// What the monitor returns for a started session.
pub enum Started {
   /// A session on pipes, which ends with its connection.
   Pipes(Spawned),
   /// A terminal session in a holder process.
   Held {
      /// What a client shows to get the session back.
      token: Token,
      /// The connection to the holder.
      link:  OwnedFd,
   },
}

/// The network process's end of the channel.
#[derive(Clone, Debug)]
pub struct Helper(Arc<Mutex<OwnedFd>>);

impl Helper {
   /// Wraps the channel the network process inherited.
   pub fn new(channel: OwnedFd) -> Self {
      Self(Arc::new(Mutex::new(channel)))
   }

   /// Sends a request and waits for its reply.
   fn call(&self, request: Request) -> Result<(Reply, Vec<OwnedFd>)> {
      let channel = self
         .0
         .lock()
         .map_err(|_| report!("a thread died while talking to the monitor"))?;

      send(&channel, &request.encode(), &[])?;
      let (bytes, descriptors) = receive(&channel)?.context("the monitor exited")?;

      match Reply::decode(&bytes)? {
         Reply::Failed(text) => bail!("monitor: {text}"),
         reply => Ok((reply, descriptors)),
      }
   }

   /// Sends a request whose answer is one descriptor.
   fn descriptor(&self, request: Request) -> Result<OwnedFd> {
      match self.call(request)? {
         (Reply::Done, descriptors) => {
            descriptors
               .into_iter()
               .next()
               .context("monitor sent no descriptor")
         },
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// The monitor's greeting and the listening socket.
   pub fn hello(&self) -> Result<(Reply, OwnedFd)> {
      match self.call(Request::Hello)? {
         (reply @ Reply::Hello { .. }, descriptors) => {
            let socket = descriptors
               .into_iter()
               .next()
               .context("monitor sent no listening socket")?;

            Ok((reply, socket))
         },
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// Asks for a host key signature over a handshake transcript.
   pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
      match self.call(Request::Sign(message.to_vec()))? {
         (Reply::Signature(signature), _) => Ok(signature),
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// Asks for the UDP socket of one connection.
   pub fn socket(&self, local: SocketAddr, remote: SocketAddr) -> Result<OwnedFd> {
      self.descriptor(Request::Socket { local, remote })
   }

   /// The monitor's [`Reply::Granted`] for a login it accepted, or `None`.
   pub fn login(
      &self,
      login: auth::Request,
      exporter: [u8; 32],
      remote: SocketAddr,
   ) -> Result<Option<Reply>> {
      let request = Request::Login {
         login,
         exporter,
         remote,
      };

      match self.call(request)? {
         (granted @ Reply::Granted { .. }, _) => Ok(Some(granted)),
         (Reply::Denied, _) => Ok(None),
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// Asks for a listening socket that reaches the client's SSH agent.
   pub fn agent(&self, grant: u64) -> Result<OwnedFd> {
      self.descriptor(Request::Agent { grant })
   }

   /// Asks the monitor to start a session.
   pub fn spawn(&self, grant: u64, open: Open) -> Result<Started> {
      match self.call(Request::Spawn { grant, open })? {
         (Reply::Spawned { session }, descriptors) => {
            Ok(Started::Pipes(Spawned {
               session,
               descriptors,
            }))
         },
         (Reply::Held { token }, descriptors) => {
            let link = descriptors
               .into_iter()
               .next()
               .context("monitor sent no holder connection")?;

            Ok(Started::Held { token, link })
         },
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// Asks for the holder of the session `token` names, which is `None` when
   /// the session is over or belongs to another account.
   pub fn attach(&self, grant: u64, token: Token) -> Result<Option<OwnedFd>> {
      match self.call(Request::Attach { grant, token })? {
         (Reply::Held { .. }, descriptors) => Ok(descriptors.into_iter().next()),
         (Reply::Denied, _) => Ok(None),
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// Asks the monitor to hang up a session.
   pub fn hangup(&self, session: u64) {
      let _ = self.call(Request::Hangup { session });
   }

   /// Ends a login.
   pub fn logout(&self, grant: u64) {
      let _ = self.call(Request::Logout { grant });
   }
}
