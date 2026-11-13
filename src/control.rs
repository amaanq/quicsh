//! Framed messages.
//!
//! - The control stream carries login, window resizes and exit statuses.
//! - Each session stream starts with one [`Message::Open`] frame. Raw standard
//!   input follows it, and raw standard output comes back.
//! - A client whose connection died starts the session stream of its next
//!   connection with [`Message::Resume`], and the server answers on that stream
//!   with [`Message::Resumed`] or [`Message::Gone`].

use std::time::Duration;

use quinn_proto::{
   Connection,
   StreamId,
   WriteError,
};

use crate::{
   auth::Request,
   error::Error,
   key::PublicKey,
   wire::{
      Reader,
      put_string,
   },
};

/// Largest frame either side accepts.
const MAX_FRAME: usize = 64 << 10;
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

/// How long a terminal session waits for a client whose connection died.
pub const DETACH_LIMIT: Duration = Duration::from_hours(1);

/// A secret that names one login, which a client shows to get its sessions
/// back on a new connection.
pub type Token = [u8; 16];

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

pub struct Open {
   /// Chosen by the client and echoed in resize and exit messages.
   pub session:  u32,
   /// `None` runs the command on pipes with a separate standard error.
   pub terminal: Option<Terminal>,
   /// `None` starts the account's login shell.
   pub command:  Option<String>,
   /// Offer the client's SSH agent to the session.
   pub agent:    bool,
}

pub enum Message {
   Request(Request),
   Accepted {
      token: Token,
   },
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
   },
   /// Asks the server to listen on a loopback port. Port 0 lets it choose.
   Listen {
      listener: u32,
      port:     u16,
   },
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
   },
   /// Opens a server stream for a program that wants the client's SSH agent.
   Agent,
   /// Opens a client stream that takes over a session from a dead connection.
   Resume {
      token:    Token,
      session:  u32,
      /// How many bytes of the session's output the client has.
      received: u64,
   },
   /// The server's answer to [`Message::Resume`], followed by the output the
   /// client is missing.
   Resumed {
      /// How many bytes of the session's input the server has.
      received: u64,
   },
   /// The server's answer to [`Message::Resume`] for a session that ended or
   /// was never there.
   Gone,
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

   let command = match reader.byte()? {
      0 => None,
      _ => Some(text(reader)?),
   };

   Ok(Open {
      session,
      terminal,
      command,
      agent: reader.byte()? != 0,
   })
}

impl Message {
   /// The length-prefixed frame to write to a stream.
   #[must_use]
   pub fn encode(&self) -> Vec<u8> {
      let mut payload = Vec::new();

      match *self {
         Self::Request(ref request) => {
            payload.push(REQUEST);
            put_string(&mut payload, request.user.as_bytes());
            put_string(&mut payload, &request.key.to_blob());
            put_string(&mut payload, &request.signature);
         },
         Self::Accepted { ref token } => {
            payload.push(ACCEPTED);
            put_string(&mut payload, token);
         },
         Self::Rejected => payload.push(REJECTED),
         Self::Open(ref open) => {
            payload.push(OPEN);
            put_u32(&mut payload, open.session);

            payload.push(u8::from(open.terminal.is_some()));
            if let Some(ref terminal) = open.terminal {
               put_string(&mut payload, terminal.name.as_bytes());
               put_size(&mut payload, terminal.size);
            }

            payload.push(u8::from(open.command.is_some()));
            if let Some(ref command) = open.command {
               put_string(&mut payload, command.as_bytes());
            }

            payload.push(u8::from(open.agent));
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
         Self::Connect { ref host, port } => {
            payload.push(CONNECT);
            put_string(&mut payload, host.as_bytes());
            put_u32(&mut payload, (port).into());
         },
         Self::Listen { listener, port } => {
            payload.push(LISTEN);
            put_u32(&mut payload, listener);
            put_u32(&mut payload, port.into());
         },
         Self::Listening { listener, port } => {
            payload.push(LISTENING);
            put_u32(&mut payload, listener);
            put_u32(&mut payload, port.into());
         },
         Self::Refused { listener } => {
            payload.push(REFUSED);
            put_u32(&mut payload, listener);
         },
         Self::Forwarded { listener } => {
            payload.push(FORWARDED);
            put_u32(&mut payload, listener);
         },
         Self::Agent => payload.push(AGENT),
         Self::Resume {
            ref token,
            session,
            received,
         } => {
            payload.push(RESUME);
            put_string(&mut payload, token);
            put_u32(&mut payload, session);
            put_string(&mut payload, &received.to_be_bytes());
         },
         Self::Resumed { received } => {
            payload.push(RESUMED);
            put_string(&mut payload, &received.to_be_bytes());
         },
         Self::Gone => payload.push(GONE),
      }

      let mut frame = Vec::with_capacity(payload.len() + 4);
      put_string(&mut frame, &payload);
      frame
   }

   /// Reads the payload of one frame, which is the frame without its length.
   ///
   /// # Errors
   ///
   /// Fails on unknown or malformed content.
   pub fn decode(payload: &[u8]) -> Result<Self, Error> {
      let mut reader = Reader::new(payload);

      let message = match reader.byte()? {
         REQUEST => {
            let user = text(&mut reader)?;

            if user.is_empty() || user.len() > MAX_USER {
               return Err(Error::Frame);
            }

            Self::Request(Request {
               user,
               key: PublicKey::from_blob(reader.string()?)?,
               signature: reader.string()?.to_vec(),
            })
         },
         ACCEPTED => {
            Self::Accepted {
               token: reader.array()?,
            }
         },
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
         CONNECT => {
            Self::Connect {
               host: text(&mut reader)?,
               port: port(&mut reader)?,
            }
         },
         LISTEN => {
            Self::Listen {
               listener: reader.u32()?,
               port:     port(&mut reader)?,
            }
         },
         LISTENING => {
            Self::Listening {
               listener: reader.u32()?,
               port:     port(&mut reader)?,
            }
         },
         REFUSED => {
            Self::Refused {
               listener: reader.u32()?,
            }
         },
         FORWARDED => {
            Self::Forwarded {
               listener: reader.u32()?,
            }
         },
         AGENT => Self::Agent,
         RESUME => {
            Self::Resume {
               token:    reader.array()?,
               session:  reader.u32()?,
               received: u64::from_be_bytes(reader.array()?),
            }
         },
         RESUMED => {
            Self::Resumed {
               received: u64::from_be_bytes(reader.array()?),
            }
         },
         GONE => Self::Gone,
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
         session:  3,
         terminal: Some(Terminal {
            name: "xterm".to_owned(),
            size: Size {
               columns: 120,
               rows:    40,
            },
         }),
         command:  Some("uname -a".to_owned()),
         agent:    true,
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
      assert_eq!(open.command.as_deref(), Some("uname -a"), "command");
      assert!(open.agent, "agent");
   }
}
