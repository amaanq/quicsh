//! The channel between the privileged monitor and the network process.
//!
//! - The network process parses everything a client sends, so it runs without
//!   privileges and holds no secrets.
//! - Whatever needs root or the host key is a [`Request`] to the monitor. Each
//!   request gets exactly one [`Reply`], which can carry file descriptors.
//! - The monitor treats requests as hostile. A network process that a client
//!   took over can start sessions only for users who logged in through it.

use std::{
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

use eyre::{
   OptionExt as _,
   Result,
   bail,
   eyre,
};
use rustix::{
   cmsg_space,
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
use ssh_quic::{
   auth,
   control::{
      Message,
      Open,
   },
   error::Error,
   wire::{
      Reader,
      put_string,
   },
};

const MAX_MESSAGE: usize = 128 << 10;
const MAX_DESCRIPTORS: usize = 4;

const HELLO: u8 = 1;
const SIGN: u8 = 2;
const SOCKET: u8 = 3;
const LOGIN: u8 = 4;
const AGENT: u8 = 5;
const SPAWN: u8 = 6;
const HANGUP: u8 = 7;
const LOGOUT: u8 = 8;

const SIGNATURE: u8 = 2;
const GRANTED: u8 = 4;
const DENIED: u8 = 5;
const SPAWNED: u8 = 6;
const DONE: u8 = 7;
const FAILED: u8 = 8;

pub enum Request {
   /// Asks for the host public key and the listening socket.
   Hello,
   /// Asks for a host key signature over a TLS handshake transcript.
   Sign(Vec<u8>),
   /// Asks for the UDP socket of one connection.
   Socket {
      local:  SocketAddr,
      remote: SocketAddr,
   },
   Login {
      login:    auth::Request,
      exporter: [u8; 32],
   },
   /// Asks for a listening agent socket that the grant's sessions can reach.
   Agent {
      grant: u64,
   },
   Spawn {
      grant: u64,
      open:  Open,
   },
   Hangup {
      session: u64,
   },
   Logout {
      grant: u64,
   },
}

pub enum Reply {
   /// Comes with the listening UDP socket.
   Hello {
      /// The host key as a `SubjectPublicKeyInfo` document.
      key:    Vec<u8>,
      listen: SocketAddr,
   },
   Signature(Vec<u8>),
   /// Stands for a successful login in later requests.
   Granted {
      grant: u64,
   },
   Denied,
   /// Comes with the terminal and a status pipe, or with standard input,
   /// output and error and a status pipe.
   Spawned {
      session: u64,
   },
   /// Success with nothing to say, or with one descriptor that the request
   /// asked for.
   Done,
   Failed(String),
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
   put_string(out, &value.to_be_bytes());
}

fn put_address(out: &mut Vec<u8>, address: SocketAddr) {
   put_string(out, address.to_string().as_bytes());
}

fn u64_from(reader: &mut Reader<'_>) -> Result<u64, Error> {
   Ok(u64::from_be_bytes(reader.array()?))
}

fn address(reader: &mut Reader<'_>) -> Result<SocketAddr, Error> {
   str::from_utf8(reader.string()?)
      .ok()
      .and_then(|text| text.parse().ok())
      .ok_or(Error::Frame)
}

impl Request {
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
         Self::Login { login, exporter } => {
            out.push(LOGIN);
            put_string(&mut out, &exporter);
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
      }

      out
   }

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

            let Message::Request(login) = Message::decode(reader.string()?)? else {
               return Err(Error::Frame);
            };

            Self::Login { login, exporter }
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
   fn encode(&self) -> Vec<u8> {
      let mut out = Vec::new();

      match self {
         Self::Hello { key, listen } => {
            out.push(HELLO);
            put_string(&mut out, key);
            put_address(&mut out, *listen);
         },
         Self::Signature(signature) => {
            out.push(SIGNATURE);
            put_string(&mut out, signature);
         },
         Self::Granted { grant } => {
            out.push(GRANTED);
            put_u64(&mut out, *grant);
         },
         Self::Denied => out.push(DENIED),
         Self::Spawned { session } => {
            out.push(SPAWNED);
            put_u64(&mut out, *session);
         },
         Self::Done => out.push(DONE),
         Self::Failed(text) => {
            out.push(FAILED);
            put_string(&mut out, text.as_bytes());
         },
      }

      out
   }

   fn decode(bytes: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(bytes);

      Ok(match reader.byte()? {
         HELLO => {
            Self::Hello {
               key:    reader.string()?.to_vec(),
               listen: address(&mut reader)?,
            }
         },
         SIGNATURE => Self::Signature(reader.string()?.to_vec()),
         GRANTED => {
            Self::Granted {
               grant: u64_from(&mut reader)?,
            }
         },
         DENIED => Self::Denied,
         SPAWNED => {
            Self::Spawned {
               session: u64_from(&mut reader)?,
            }
         },
         DONE => Self::Done,
         FAILED => Self::Failed(String::from_utf8_lossy(reader.string()?).into_owned()),
         _ => return Err(Error::Frame),
      })
   }
}

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

/// Answers requests with `handle` until the network process goes away. A
/// request that fails is reported to the network process and serving goes on.
pub fn serve(
   channel: &OwnedFd,
   mut handle: impl FnMut(Request) -> Result<(Reply, Vec<OwnedFd>)>,
) -> Result<()> {
   while let Some((bytes, _)) = receive(channel)? {
      let (reply, descriptors) = Request::decode(&bytes)
         .map_err(Into::into)
         .and_then(&mut handle)
         .unwrap_or_else(|error| (Reply::Failed(format!("{error:#}")), Vec::new()));

      let borrowed: Vec<_> = descriptors.iter().map(OwnedFd::as_fd).collect();
      send(channel, &reply.encode(), &borrowed)?;
   }

   Ok(())
}

/// What the monitor returns for a started session.
pub struct Spawned {
   pub session:     u64,
   pub descriptors: Vec<OwnedFd>,
}

/// The network process's end of the channel.
#[derive(Clone, Debug)]
pub struct Helper(Arc<Mutex<OwnedFd>>);

impl Helper {
   pub fn new(channel: OwnedFd) -> Self {
      Self(Arc::new(Mutex::new(channel)))
   }

   fn call(&self, request: Request) -> Result<(Reply, Vec<OwnedFd>)> {
      let channel = self
         .0
         .lock()
         .map_err(|_| eyre!("a thread died while talking to the monitor"))?;

      send(&channel, &request.encode(), &[])?;
      let (bytes, descriptors) = receive(&channel)?.ok_or_eyre("the monitor exited")?;

      match Reply::decode(&bytes)? {
         Reply::Failed(text) => bail!("monitor: {text}"),
         reply => Ok((reply, descriptors)),
      }
   }

   fn descriptor(&self, request: Request) -> Result<OwnedFd> {
      match self.call(request)? {
         (Reply::Done, descriptors) => {
            descriptors
               .into_iter()
               .next()
               .ok_or_eyre("monitor sent no descriptor")
         },
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   /// The host public key, the listening address and its socket.
   pub fn hello(&self) -> Result<(Vec<u8>, SocketAddr, OwnedFd)> {
      match self.call(Request::Hello)? {
         (Reply::Hello { key, listen }, descriptors) => {
            let socket = descriptors
               .into_iter()
               .next()
               .ok_or_eyre("monitor sent no listening socket")?;

            Ok((key, listen, socket))
         },
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
      match self.call(Request::Sign(message.to_vec()))? {
         (Reply::Signature(signature), _) => Ok(signature),
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   pub fn socket(&self, local: SocketAddr, remote: SocketAddr) -> Result<OwnedFd> {
      self.descriptor(Request::Socket { local, remote })
   }

   /// The grant for a login the monitor accepted, or `None`.
   pub fn login(&self, login: auth::Request, exporter: [u8; 32]) -> Result<Option<u64>> {
      match self.call(Request::Login { login, exporter })? {
         (Reply::Granted { grant }, _) => Ok(Some(grant)),
         (Reply::Denied, _) => Ok(None),
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   pub fn agent(&self, grant: u64) -> Result<OwnedFd> {
      self.descriptor(Request::Agent { grant })
   }

   pub fn spawn(&self, grant: u64, open: Open) -> Result<Spawned> {
      match self.call(Request::Spawn { grant, open })? {
         (Reply::Spawned { session }, descriptors) => {
            Ok(Spawned {
               session,
               descriptors,
            })
         },
         _ => bail!("unexpected reply from the monitor"),
      }
   }

   pub fn hangup(&self, session: u64) {
      let _ = self.call(Request::Hangup { session });
   }

   pub fn logout(&self, grant: u64) {
      let _ = self.call(Request::Logout { grant });
   }
}
