use std::{
   collections::HashMap,
   fs,
   net::SocketAddr,
   path::{
      Path,
      PathBuf,
   },
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
      Deframer,
      Message,
      Request,
      exporter,
   },
   error::Error,
   key::private_from_openssh,
   tls,
   transport::{
      App,
      Transport,
      Tuning,
      drain,
   },
};

const LOGIN_GRACE: Duration = Duration::from_secs(120);
const MAX_ATTEMPTS: u32 = 6;
const PROTOCOL_ERROR: VarInt = VarInt::from_u32(1);
const AUTH_FAILED: VarInt = VarInt::from_u32(2);

struct Options {
   listen:          SocketAddr,
   host_key:        PathBuf,
   authorized_keys: Option<PathBuf>,
}

impl Options {
   fn parse() -> Result<Self> {
      let mut options = Self {
         listen:          SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
         host_key:        PathBuf::from("/etc/ssh/ssh_host_ed25519_key"),
         authorized_keys: None,
      };

      let mut parser = Parser::from_env();

      while let Some(argument) = parser.next()? {
         match argument {
            Arg::Long("listen") => options.listen = parser.value()?.parse()?,
            Arg::Long("host-key") => options.host_key = parser.value()?.into(),
            Arg::Long("authorized-keys") => options.authorized_keys = Some(parser.value()?.into()),
            Arg::Long("help") => {
               println!(
                  "usage: ssh-quicd [--listen ADDR:PORT] [--host-key FILE] [--authorized-keys \
                   FILE]"
               );
               std::process::exit(0);
            },
            other => return Err(other.unexpected().into()),
         }
      }

      Ok(options)
   }
}

struct Peer {
   control:  Option<StreamId>,
   deframer: Deframer,
   attempts: u32,
   user:     Option<String>,
   deadline: Instant,
}

struct Server {
   peers:           HashMap<ConnectionHandle, Peer>,
   authorized_keys: Option<PathBuf>,
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
   fn readable(
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
         let Message::Request(request) = message else {
            bail!("unexpected control message");
         };

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
      match event {
         Event::Connected => {
            self.peers.insert(handle, Peer {
               control:  None,
               deframer: Deframer::default(),
               attempts: 0,
               user:     None,
               deadline: now + LOGIN_GRACE,
            });
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
            while let Some(id) = connection.streams().accept(Dir::Bi) {
               let Some(peer) = self.peers.get_mut(&handle) else {
                  bail!("stream before the handshake finished");
               };

               if peer.control.is_some() {
                  bail!("only the control stream is supported so far");
               }

               peer.control = Some(id);
               self.readable(now, handle, connection)?;
            }
         },
         Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
            bail!("unidirectional streams are not part of the protocol");
         },
         Event::Stream(StreamEvent::Readable { .. }) => self.readable(now, handle, connection)?,
         Event::ConnectionLost { .. } => {
            self.peers.remove(&handle);
         },
         _ => {},
      }

      Ok(())
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
      }

      Ok(())
   }

   fn tick(
      &mut self,
      now: Instant,
      handle: ConnectionHandle,
      connection: &mut Connection,
   ) -> Result<Option<Instant>> {
      let Some(peer) = self.peers.get(&handle).filter(|peer| peer.user.is_none()) else {
         return Ok(None);
      };

      if now >= peer.deadline && !connection.is_closed() {
         connection.close(now, AUTH_FAILED, Bytes::from_static(b"login timed out"));
         return Ok(None);
      }

      Ok(Some(peer.deadline))
   }

   fn done(&self) -> bool {
      false
   }
}

fn main() -> Result<()> {
   let options = Options::parse()?;

   let key_text = fs::read_to_string(&options.host_key)
      .wrap_err_with(|| format!("reading host key {}", options.host_key.display()))?;
   let crypto = tls::server(&private_from_openssh(&key_text)?)?;

   let mut server = Server {
      peers:           HashMap::new(),
      authorized_keys: options.authorized_keys,
   };

   let mut transport = Transport::listen(options.listen, crypto, Tuning::default())
      .wrap_err_with(|| format!("listening on {}", options.listen))?;

   println!("listening on udp {}", options.listen);
   transport.run(&mut server)
}
