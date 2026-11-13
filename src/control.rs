//! Framed messages.
//!
//! - The control stream carries login, window resizes and exit statuses.
//! - Each session stream starts with one [`Message::Open`] frame. Raw standard
//!   input follows it, and raw standard output comes back.

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

const MAX_FRAME: usize = 64 << 10;
const MAX_USER: usize = 64;
const REQUEST: u8 = 1;
const ACCEPTED: u8 = 2;
const REJECTED: u8 = 3;
const OPEN: u8 = 4;
const RESIZE: u8 = 5;
const EXIT: u8 = 6;
const CONNECT: u8 = 7;
const LISTEN: u8 = 8;
const LISTENING: u8 = 9;
const REFUSED: u8 = 10;
const FORWARDED: u8 = 11;
const AGENT: u8 = 12;

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
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
   out.extend_from_slice(&value.to_be_bytes());
}

fn put_size(out: &mut Vec<u8>, size: Size) {
   put_u32(out, size.columns.into());
   put_u32(out, size.rows.into());
}

fn size(reader: &mut Reader<'_>) -> Result<Size, Error> {
   Ok(Size {
      columns: reader.u32()?.try_into().map_err(|_| Error::Frame)?,
      rows:    reader.u32()?.try_into().map_err(|_| Error::Frame)?,
   })
}

fn port(reader: &mut Reader<'_>) -> Result<u16, Error> {
   reader.u32()?.try_into().map_err(|_| Error::Frame)
}

fn text(reader: &mut Reader<'_>) -> Result<String, Error> {
   let bytes = reader.string()?;
   Ok(str::from_utf8(bytes).map_err(|_| Error::Frame)?.to_owned())
}

impl Message {
   /// The length-prefixed frame to write to a stream.
   #[must_use]
   pub fn encode(&self) -> Vec<u8> {
      let mut payload = Vec::new();

      match self {
         Self::Request(request) => {
            payload.push(REQUEST);
            put_string(&mut payload, request.user.as_bytes());
            put_string(&mut payload, &request.key.to_blob());
            put_string(&mut payload, &request.signature);
         },
         Self::Accepted => payload.push(ACCEPTED),
         Self::Rejected => payload.push(REJECTED),
         Self::Open(open) => {
            payload.push(OPEN);
            put_u32(&mut payload, open.session);

            payload.push(u8::from(open.terminal.is_some()));
            if let Some(terminal) = &open.terminal {
               put_string(&mut payload, terminal.name.as_bytes());
               put_size(&mut payload, terminal.size);
            }

            payload.push(u8::from(open.command.is_some()));
            if let Some(command) = &open.command {
               put_string(&mut payload, command.as_bytes());
            }

            payload.push(u8::from(open.agent));
         },
         Self::Resize { session, size } => {
            payload.push(RESIZE);
            put_u32(&mut payload, *session);
            put_size(&mut payload, *size);
         },
         Self::Exit { session, status } => {
            payload.push(EXIT);
            put_u32(&mut payload, *session);
            put_u32(&mut payload, *status);
         },
         Self::Connect { host, port } => {
            payload.push(CONNECT);
            put_string(&mut payload, host.as_bytes());
            put_u32(&mut payload, (*port).into());
         },
         Self::Listen { listener, port } => {
            payload.push(LISTEN);
            put_u32(&mut payload, *listener);
            put_u32(&mut payload, (*port).into());
         },
         Self::Listening { listener, port } => {
            payload.push(LISTENING);
            put_u32(&mut payload, *listener);
            put_u32(&mut payload, (*port).into());
         },
         Self::Refused { listener } => {
            payload.push(REFUSED);
            put_u32(&mut payload, *listener);
         },
         Self::Forwarded { listener } => {
            payload.push(FORWARDED);
            put_u32(&mut payload, *listener);
         },
         Self::Agent => payload.push(AGENT),
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
         ACCEPTED => Self::Accepted,
         REJECTED => Self::Rejected,
         OPEN => {
            let session = reader.u32()?;

            let terminal = match reader.byte()? {
               0 => None,
               _ => {
                  Some(Terminal {
                     name: text(&mut reader)?,
                     size: size(&mut reader)?,
                  })
               },
            };

            let command = match reader.byte()? {
               0 => None,
               _ => Some(text(&mut reader)?),
            };

            Self::Open(Open {
               session,
               terminal,
               command,
               agent: reader.byte()? != 0,
            })
         },
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
