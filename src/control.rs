//! Framed messages.
//!
//! - The control stream carries login, window resizes and exit statuses.
//! - Each session stream starts with one [`Message::Open`] frame. Raw standard
//!   input follows it, and raw standard output comes back.
//! - A client whose connection died starts the session stream of its next
//!   connection with [`Message::Resume`], and the server answers on that stream
//!   with [`Message::Resumed`] or [`Message::Gone`]. Both sides say with
//!   [`Message::Taken`] how much of a session's data they have, so that the
//!   other may forget it.
//! - A forwarded connection continues the same way. The side that opens its
//!   stream names it with a [`Handle`], and the client shows that handle's
//!   token in a [`Message::Resume`] on its next connection.

use std::time::Duration;

use quinn_proto::{
   Connection,
   StreamId,
   WriteError,
};

use crate::{
   auth::Request,
   certificate::Certificate,
   error::Error,
   key::PublicKey,
   wire::{
      Reader,
      put_string,
   },
};

/// Largest frame either side accepts.
const MAX_FRAME: usize = 64 << 10;
/// Most environment variables a session may ask for.
const MAX_ENVIRONMENT: u32 = 256;
/// Longest account name a login may carry.
const MAX_USER: usize = 64;
/// Tag of [`Message::Request`].
const REQUEST: u8 = 1;
/// Tag of [`Message::Accepted`].
const ACCEPTED: u8 = 2;
/// Tag of [`Message::Rejected`].
const REJECTED: u8 = 3;
/// Tag of [`Message::Open`].
const OPEN: u8 = 4;
/// Tag of [`Message::Resize`].
const RESIZE: u8 = 5;
/// Tag of [`Message::Exit`].
const EXIT: u8 = 6;
/// Tag of [`Message::Connect`].
const CONNECT: u8 = 7;
/// Tag of [`Message::Listen`].
const LISTEN: u8 = 8;
/// Tag of [`Message::Listening`].
const LISTENING: u8 = 9;
/// Tag of [`Message::Refused`].
const REFUSED: u8 = 10;
/// Tag of [`Message::Forwarded`].
const FORWARDED: u8 = 11;
/// Tag of [`Message::Agent`].
const AGENT: u8 = 12;
/// Tag of [`Message::Resume`].
const RESUME: u8 = 13;
/// Tag of [`Message::Resumed`].
const RESUMED: u8 = 14;
/// Tag of [`Message::Gone`].
const GONE: u8 = 15;
/// Tag of [`Message::Resumable`].
const RESUMABLE: u8 = 16;
/// Tag of [`Message::Failed`].
const FAILED: u8 = 17;
/// Tag of [`Message::Associate`].
const ASSOCIATE: u8 = 18;
/// Tag of [`Message::Taken`].
const TAKEN: u8 = 19;
/// Tag of [`Message::Close`].
const CLOSE: u8 = 20;
/// Tag of [`Message::Reach`].
const REACH: u8 = 21;
/// Tag of [`Message::Bind`].
const BIND: u8 = 22;
/// Tag of [`Message::Certify`].
const CERTIFY: u8 = 23;
/// Tag of [`Message::HostCertificate`].
const HOST_CERTIFICATE: u8 = 24;
/// Tag of [`Message::Upgraded`].
const UPGRADED: u8 = 25;

/// How long a session waits for a client whose connection died.
pub const DETACH_LIMIT: Duration = Duration::from_hours(1);

/// A secret that names one session, which a client shows to get the
/// session back on a new connection.
pub type Token = [u8; 16];

/// Set in the label of a forwarded connection whose stream the server
/// opened, so that its labels never meet the ones a client hands out.
pub const SERVER_LABEL: u32 = 1 << 31;

/// What names a forwarded connection to both sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
   /// The number [`Message::Taken`] counts the forward's data under.
   pub label: u32,
   /// The secret that continues the forward on a new connection.
   pub token: Token,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
   pub columns: u16,
   pub rows:    u16,
}

pub struct Terminal {
   /// The client's `TERM`.
   pub name: String,
   pub size: Size,
}

/// What a session runs.
pub enum Program {
   /// The account's login shell.
   Shell,
   /// A command line for the login shell.
   Command(String),
   /// A service the server knows by name, such as `sftp`.
   Subsystem(String),
}

pub struct Open {
   /// Chosen by the client and echoed in resize and exit messages.
   pub session:     u32,
   /// `None` runs the command on pipes with a separate standard error.
   pub terminal:    Option<Terminal>,
   pub program:     Program,
   /// Offer the client's SSH agent to the session.
   pub agent:       bool,
   /// Environment variables for the session, which the server may drop.
   pub environment: Vec<(String, String)>,
}

pub enum Message {
   Request(Request),
   Accepted,
   Rejected,
   Open(Open),
   Resize {
      session: u32,
      size:    Size,
   },
   Exit {
      session: u32,
      status:  u32,
   },
   /// Opens a client stream that the server joins to a TCP connection.
   Connect {
      host: String,
      port: u16,
      kept: Handle,
   },
   /// Opens a client stream that the server joins to a UDP socket. Each
   /// datagram travels behind two bytes that hold its length.
   Associate {
      host: String,
      port: u16,
   },
   /// Opens a client stream that the server joins to a Unix socket, which
   /// it connects to as the account.
   Reach {
      path: String,
      kept: Handle,
   },
   /// Asks the server to listen on a loopback port. Port 0 lets it choose.
   Listen {
      listener: u32,
      port:     u16,
   },
   /// Asks the server to listen on a Unix socket that the account owns.
   Bind {
      listener: u32,
      path:     String,
   },
   /// The port is zero for a Unix socket.
   Listening {
      listener: u32,
      port:     u16,
   },
   Refused {
      listener: u32,
   },
   /// Opens a server stream for a connection that `listener` accepted.
   Forwarded {
      listener: u32,
      kept:     Handle,
   },
   /// Opens a server stream for a program that wants the client's SSH agent.
   Agent,
   /// Opens a client stream that takes over a session from a dead connection.
   Resume {
      token:    Token,
      session:  u32,
      /// How many bytes of the session's output the client has.
      received: u64,
      /// How many bytes of the session's standard error the client has.
      errors:   u64,
   },
   /// The server's answer to [`Message::Resume`], followed by the output the
   /// client is missing.
   Resumed {
      /// How many bytes of the session's input the server has.
      received: u64,
      /// How many bytes of output the server no longer has for the client.
      skipped:  u64,
   },
   /// The server's answer to [`Message::Resume`] for a session that ended or
   /// was never there.
   Gone,
   /// The server's answer to [`Message::Resume`] for a session that an
   /// older server started in a way this one cannot continue.
   Upgraded,
   /// Tells the client that a session can be resumed, and with what.
   Resumable {
      session: u32,
      token:   Token,
   },
   /// The server did not start the session, and why.
   Failed {
      session: u32,
      reason:  String,
   },
   /// Says how much of a session's data the sender has, so that the other
   /// side may forget it. The client counts output and standard error, and
   /// the server counts input and leaves `errors` at zero.
   Taken {
      session: u32,
      taken:   u64,
      errors:  u64,
   },
   /// The client is done with a session, which it either saw to its end or
   /// gave up on. The server ends its side of it.
   Close {
      session: u32,
   },
   /// Asks the server, before the login, what a certificate authority says
   /// about its host key.
   Certify,
   /// The server's host certificate, which is empty when it has none.
   HostCertificate(Vec<u8>),
}

/// Appends a count and that many pairs of a name and a value.
fn put_environment(out: &mut Vec<u8>, environment: &[(String, String)]) {
   put_u32(out, u32::try_from(environment.len()).unwrap_or(u32::MAX));

   for pair in environment {
      put_string(out, pair.0.as_bytes());
      put_string(out, pair.1.as_bytes());
   }
}

/// Appends the tag and the fields of a message that names a host and a port.
fn put_target(out: &mut Vec<u8>, tag: u8, host: &str, port: u16) {
   out.push(tag);
   put_string(out, host.as_bytes());
   put_u32(out, port.into());
}

/// Appends the tag and the fields of a message that carries a session and
/// two counts of its data.
fn put_counts(out: &mut Vec<u8>, tag: u8, session: u32, counts: [u64; 2]) {
   out.push(tag);
   put_u32(out, session);

   for count in counts {
      put_string(out, &count.to_be_bytes());
   }
}

/// Appends the tag and the fields of a message that names a listener and
/// its port.
fn put_listener(out: &mut Vec<u8>, tag: u8, listener: u32, port: u16) {
   out.push(tag);
   put_u32(out, listener);
   put_u32(out, port.into());
}

/// Writes a message that opens a forwarded connection, with its handle last.
fn put_forward(out: &mut Vec<u8>, message: &Message) {
   let kept = match *message {
      Message::Connect {
         ref host,
         port,
         kept,
      } => {
         put_target(out, CONNECT, host, port);
         kept
      },
      Message::Reach { ref path, kept } => {
         out.push(REACH);
         put_string(out, path.as_bytes());
         kept
      },
      Message::Forwarded { listener, kept } => {
         put_numbered(out, FORWARDED, listener);
         kept
      },
      _ => return,
   };

   put_u32(out, kept.label);
   put_string(out, &kept.token);
}

/// Appends the tag and the one number of a message that carries no more.
fn put_numbered(out: &mut Vec<u8>, tag: u8, number: u32) {
   out.push(tag);
   put_u32(out, number);
}

/// Appends a 32-bit number.
fn put_u32(out: &mut Vec<u8>, value: u32) {
   out.extend_from_slice(&value.to_be_bytes());
}

/// Appends a terminal size.
fn put_size(out: &mut Vec<u8>, size: Size) {
   put_u32(out, size.columns.into());
   put_u32(out, size.rows.into());
}

/// Reads a terminal size.
fn size(reader: &mut Reader<'_>) -> Result<Size, Error> {
   Ok(Size {
      columns: reader.u32()?.try_into().map_err(|_| Error::Frame)?,
      rows:    reader.u32()?.try_into().map_err(|_| Error::Frame)?,
   })
}

/// Reads a port number.
fn port(reader: &mut Reader<'_>) -> Result<u16, Error> {
   reader.u32()?.try_into().map_err(|_| Error::Frame)
}

/// Reads a UTF-8 string.
fn text(reader: &mut Reader<'_>) -> Result<String, Error> {
   let bytes = reader.string()?;
   Ok(str::from_utf8(bytes).map_err(|_| Error::Frame)?.to_owned())
}

/// Appends the tag and the fields of [`Message::Request`].
fn put_request(out: &mut Vec<u8>, request: &Request) {
   out.push(REQUEST);
   put_string(out, request.user.as_bytes());
   put_string(out, &request.key.to_blob());
   put_string(out, &request.signature);

   let certificate = request.certificate.as_deref();
   put_string(out, certificate.map_or(&[], Certificate::to_blob));
}

/// Reads the fields of [`Message::Request`].
fn request(reader: &mut Reader<'_>) -> Result<Request, Error> {
   let user = text(reader)?;

   if user.is_empty() || user.len() > MAX_USER {
      return Err(Error::Frame);
   }

   Ok(Request {
      user,
      key: PublicKey::from_blob(reader.string()?)?,
      signature: reader.string()?.to_vec(),
      certificate: Some(reader.string()?)
         .filter(|blob| !blob.is_empty())
         .map(Certificate::from_blob)
         .transpose()?
         .map(Box::new),
   })
}

/// Reads the fields of [`Message::Open`].
fn open(reader: &mut Reader<'_>) -> Result<Open, Error> {
   let session = reader.u32()?;

   let terminal = match reader.byte()? {
      0 => None,
      _ => {
         Some(Terminal {
            name: text(reader)?,
            size: size(reader)?,
         })
      },
   };

   let program = match reader.byte()? {
      0 => Program::Shell,
      1 => Program::Command(text(reader)?),
      2 => Program::Subsystem(text(reader)?),
      _ => return Err(Error::Frame),
   };

   let agent = reader.byte()? != 0;
   let count = reader.u32()?;

   if count > MAX_ENVIRONMENT {
      return Err(Error::Frame);
   }

   let mut environment = Vec::new();

   for _ in 0..count {
      environment.push((text(reader)?, text(reader)?));
   }

   Ok(Open {
      session,
      terminal,
      program,
      agent,
      environment,
   })
}

impl Message {
   /// The length-prefixed frame to write to a stream.
   #[must_use]
   pub fn encode(&self) -> Vec<u8> {
      let mut payload = Vec::new();

      match *self {
         Self::Request(ref request) => put_request(&mut payload, request),
         Self::Accepted => payload.push(ACCEPTED),
         Self::Rejected => payload.push(REJECTED),
         Self::Open(ref open) => {
            payload.push(OPEN);
            put_u32(&mut payload, open.session);

            payload.push(u8::from(open.terminal.is_some()));
            if let Some(ref terminal) = open.terminal {
               put_string(&mut payload, terminal.name.as_bytes());
               put_size(&mut payload, terminal.size);
            }

            match open.program {
               Program::Shell => payload.push(0),
               Program::Command(ref line) => {
                  payload.push(1);
                  put_string(&mut payload, line.as_bytes());
               },
               Program::Subsystem(ref name) => {
                  payload.push(2);
                  put_string(&mut payload, name.as_bytes());
               },
            }

            payload.push(u8::from(open.agent));
            put_environment(&mut payload, &open.environment);
         },
         Self::Resize { session, size } => {
            payload.push(RESIZE);
            put_u32(&mut payload, session);
            put_size(&mut payload, size);
         },
         Self::Exit { session, status } => {
            payload.push(EXIT);
            put_u32(&mut payload, session);
            put_u32(&mut payload, status);
         },
         Self::Connect { .. } | Self::Reach { .. } | Self::Forwarded { .. } => {
            put_forward(&mut payload, self);
         },
         Self::Associate { ref host, port } => put_target(&mut payload, ASSOCIATE, host, port),
         Self::Bind { listener, ref path } => {
            put_numbered(&mut payload, BIND, listener);
            put_string(&mut payload, path.as_bytes());
         },
         Self::Listen { listener, port } => put_listener(&mut payload, LISTEN, listener, port),
         Self::Listening { listener, port } => {
            put_listener(&mut payload, LISTENING, listener, port);
         },
         Self::Refused { listener } => put_numbered(&mut payload, REFUSED, listener),
         Self::Agent => payload.push(AGENT),
         Self::Resume {
            ref token,
            session,
            received,
            errors,
         } => {
            put_counts(&mut payload, RESUME, session, [received, errors]);
            put_string(&mut payload, token);
         },
         Self::Taken {
            session,
            taken,
            errors,
         } => put_counts(&mut payload, TAKEN, session, [taken, errors]),
         Self::Close { session } => put_numbered(&mut payload, CLOSE, session),
         Self::Certify => payload.push(CERTIFY),
         Self::HostCertificate(ref blob) => {
            payload.push(HOST_CERTIFICATE);
            put_string(&mut payload, blob);
         },
         Self::Resumed { received, skipped } => {
            payload.push(RESUMED);
            put_string(&mut payload, &received.to_be_bytes());
            put_string(&mut payload, &skipped.to_be_bytes());
         },
         Self::Gone => payload.push(GONE),
         Self::Upgraded => payload.push(UPGRADED),
         Self::Resumable { session, ref token } => {
            payload.push(RESUMABLE);
            put_u32(&mut payload, session);
            put_string(&mut payload, token);
         },
         Self::Failed {
            session,
            ref reason,
         } => {
            payload.push(FAILED);
            put_u32(&mut payload, session);
            put_string(&mut payload, reason.as_bytes());
         },
      }

      let mut frame = Vec::with_capacity(payload.len() + 4);
      put_string(&mut frame, &payload);
      frame
   }

   /// Reads the rest of a message that [`put_counts`] started.
   fn counted(tag: u8, reader: &mut Reader<'_>) -> Result<Self, Error> {
      let session = reader.u32()?;
      let first = u64::from_be_bytes(reader.array()?);
      let errors = u64::from_be_bytes(reader.array()?);

      Ok(if tag == RESUME {
         Self::Resume {
            token: reader.array()?,
            session,
            received: first,
            errors,
         }
      } else {
         Self::Taken {
            session,
            taken: first,
            errors,
         }
      })
   }

   /// Reads the rest of a message that [`put_listener`] started.
   fn listener(tag: u8, reader: &mut Reader<'_>) -> Result<Self, Error> {
      let listener = reader.u32()?;
      let port = port(reader)?;

      Ok(if tag == LISTEN {
         Self::Listen { listener, port }
      } else {
         Self::Listening { listener, port }
      })
   }

   /// Reads the rest of a message that [`put_forward`] started.
   fn forward(tag: u8, reader: &mut Reader<'_>) -> Result<Self, Error> {
      let handle = |source: &mut Reader<'_>| {
         Ok::<Handle, Error>(Handle {
            label: source.u32()?,
            token: source.array()?,
         })
      };

      Ok(match tag {
         CONNECT => {
            Self::Connect {
               host: text(reader)?,
               port: port(reader)?,
               kept: handle(reader)?,
            }
         },
         REACH => {
            Self::Reach {
               path: text(reader)?,
               kept: handle(reader)?,
            }
         },
         _ => {
            Self::Forwarded {
               listener: reader.u32()?,
               kept:     handle(reader)?,
            }
         },
      })
   }

   /// Reads the payload of one frame, which is the frame without its length.
   ///
   /// # Errors
   ///
   /// Fails on unknown or malformed content.
   pub fn decode(payload: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(payload);

      let message = match reader.byte()? {
         REQUEST => Self::Request(request(&mut reader)?),
         ACCEPTED => Self::Accepted,
         REJECTED => Self::Rejected,
         OPEN => Self::Open(open(&mut reader)?),
         RESIZE => {
            Self::Resize {
               session: reader.u32()?,
               size:    size(&mut reader)?,
            }
         },
         EXIT => {
            Self::Exit {
               session: reader.u32()?,
               status:  reader.u32()?,
            }
         },
         tag @ (CONNECT | REACH | FORWARDED) => Self::forward(tag, &mut reader)?,
         ASSOCIATE => {
            Self::Associate {
               host: text(&mut reader)?,
               port: port(&mut reader)?,
            }
         },
         BIND => {
            Self::Bind {
               listener: reader.u32()?,
               path:     text(&mut reader)?,
            }
         },
         tag @ (LISTEN | LISTENING) => Self::listener(tag, &mut reader)?,
         REFUSED => {
            Self::Refused {
               listener: reader.u32()?,
            }
         },
         AGENT => Self::Agent,
         tag @ (RESUME | TAKEN) => Self::counted(tag, &mut reader)?,
         CLOSE => {
            Self::Close {
               session: reader.u32()?,
            }
         },
         CERTIFY => Self::Certify,
         HOST_CERTIFICATE => Self::HostCertificate(reader.string()?.to_vec()),
         RESUMED => {
            Self::Resumed {
               received: u64::from_be_bytes(reader.array()?),
               skipped:  u64::from_be_bytes(reader.array()?),
            }
         },
         GONE => Self::Gone,
         UPGRADED => Self::Upgraded,
         RESUMABLE => {
            Self::Resumable {
               session: reader.u32()?,
               token:   reader.array()?,
            }
         },
         FAILED => {
            Self::Failed {
               session: reader.u32()?,
               reason:  text(&mut reader)?,
            }
         },
         _ => return Err(Error::Frame),
      };

      if reader.is_empty() {
         Ok(message)
      } else {
         Err(Error::Frame)
      }
   }
}

/// Control messages waiting for the connection's send window, which bulk
/// data on other streams can use up.
#[derive(Default)]
pub struct Outbox(Vec<u8>);

impl Outbox {
   pub fn push(&mut self, message: &Message) {
      self.0.extend_from_slice(&message.encode());
   }

   /// Writes as much as `stream` accepts now.
   ///
   /// # Errors
   ///
   /// Fails when the peer stopped reading the stream.
   pub fn flush(&mut self, connection: &mut Connection, stream: StreamId) -> Result<(), Error> {
      if self.0.is_empty() {
         return Ok(());
      }

      match connection.send_stream(stream).write(&self.0) {
         Ok(written) => {
            self.0.drain(..written);
            Ok(())
         },
         Err(WriteError::Blocked) => Ok(()),
         Err(error) => Err(Error::Write(error)),
      }
   }
}

/// Reassembles stream bytes into messages.
#[derive(Default)]
pub struct Deframer(Vec<u8>);

impl Deframer {
   pub fn push(&mut self, bytes: &[u8]) {
      self.0.extend_from_slice(bytes);
   }

   /// # Errors
   ///
   /// Fails on a frame over the size limit or with unknown content.
   pub fn pop(&mut self) -> Result<Option<Message>, Error> {
      let Some((prefix, rest)) = self.0.split_first_chunk::<4>() else {
         return Ok(None);
      };

      let length = usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| Error::Frame)?;

      if length > MAX_FRAME {
         return Err(Error::Frame);
      }

      let Some(payload) = rest.get(..length) else {
         return Ok(None);
      };

      let message = Message::decode(payload)?;
      self.0.drain(..length + 4);
      Ok(Some(message))
   }

   /// The bytes that followed the last frame, which on a session stream are
   /// the start of standard input.
   #[must_use]
   pub fn into_rest(self) -> Vec<u8> {
      self.0
   }
}

#[cfg(test)]
mod tests {
   use crate::{
      control::{
         Deframer,
         MAX_FRAME,
         Message,
         Open,
         Outbox,
         Program,
         Size,
         Terminal,
      },
      error::Error,
   };

   /// A frame that arrives in pieces decodes once it is whole, and the bytes
   /// after it are kept.
   #[test]
   fn frame_split_across_reads() {
      let mut outbox = Outbox::default();
      outbox.push(&Message::Listen {
         listener: 7,
         port:     8080,
      });

      let (head, tail) = outbox.0.split_at(3);
      let mut deframer = Deframer::default();
      deframer.push(head);

      assert!(
         deframer.pop().unwrap().is_none(),
         "length prefix is incomplete"
      );

      deframer.push(tail);
      deframer.push(b"input");

      assert!(
         matches!(
            deframer.pop().unwrap(),
            Some(Message::Listen {
               listener: 7,
               port:     8080,
            })
         ),
         "whole frame"
      );
      assert_eq!(deframer.into_rest(), b"input", "bytes after the frame");
   }

   /// A length over the limit fails before any payload is buffered.
   #[test]
   fn oversize_frame_is_refused() {
      let mut deframer = Deframer::default();
      deframer.push(
         &u32::try_from(MAX_FRAME + 1)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
      );

      assert!(
         matches!(deframer.pop(), Err(Error::Frame)),
         "length over the limit"
      );
   }

   /// The message with the most optional fields survives encoding.
   #[test]
   fn open_round_trips() {
      let mut outbox = Outbox::default();
      outbox.push(&Message::Open(Open {
         session:     3,
         terminal:    Some(Terminal {
            name: "xterm".to_owned(),
            size: Size {
               columns: 120,
               rows:    40,
            },
         }),
         program:     Program::Command("uname -a".to_owned()),
         agent:       true,
         environment: vec![("LANG".to_owned(), "C.UTF-8".to_owned())],
      }));

      let mut deframer = Deframer::default();
      deframer.push(&outbox.0);

      let Some(Message::Open(open)) = deframer.pop().unwrap() else {
         panic!("expected an open message");
      };
      let size = open.terminal.as_ref().map(|terminal| terminal.size);

      assert_eq!(open.session, 3, "session");
      assert_eq!(
         open.terminal.map(|terminal| terminal.name).as_deref(),
         Some("xterm"),
         "TERM"
      );
      assert_eq!(
         size.map(|sent| (sent.columns, sent.rows)),
         Some((120, 40)),
         "size"
      );
      assert!(
         matches!(open.program, Program::Command(ref line) if line == "uname -a"),
         "command"
      );
      assert!(open.agent, "agent");
   }
}
