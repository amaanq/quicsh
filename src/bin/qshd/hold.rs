//! The process that owns one session, so that the session outlives the
//! server.
//!
//! - The monitor starts a holder for each session and hands it a listening
//!   socket in a directory only the monitor can enter.
//! - The holder opens the terminal or the pipes, starts the session and then
//!   becomes the session's account. It keeps the output the client may lack and
//!   counts the input, which is what a client needs to continue after its
//!   connection or the server went away. A terminal's output is kept up to a
//!   limit, and a pipe's until the client confirms it, so a pipe continues
//!   without a gap.
//! - The network process reaches a holder through a connection the monitor
//!   makes for it, and speaks [`Packet`]s over it. A new connection replaces
//!   the old one.
//! - The holder also owns the socket that reaches the client's SSH agent, so
//!   the path the session knows keeps working for every later connection.

use std::{
   collections::VecDeque,
   env,
   fs::{
      self,
      DirBuilder,
      File,
   },
   io::{
      self,
      IoSlice,
      IoSliceMut,
      Read as _,
      Write as _,
   },
   mem::MaybeUninit,
   ops::ControlFlow,
   os::{
      fd::{
         AsFd as _,
         OwnedFd,
      },
      unix::{
         fs::{
            DirBuilderExt as _,
            fchown,
         },
         net::UnixListener,
      },
   },
   path::PathBuf,
   process::{
      Command,
      Stdio,
   },
   thread,
   time::{
      Duration,
      Instant,
   },
};

use bytes::{
   Buf as _,
   Bytes,
};
use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   bail,
   report,
};
use quicsh::{
   auth::Account,
   control::{
      DETACH_LIMIT,
      Size,
      Terminal,
   },
   error::Error,
   relay::Tail,
   wire::Reader,
};
use ring::rand::{
   SecureRandom as _,
   SystemRandom,
};
use rustix::{
   cmsg_space,
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   io::{
      Errno,
      ioctl_fionbio,
      read,
      write,
   },
   net::{
      RecvAncillaryBuffer,
      RecvAncillaryMessage,
      RecvFlags,
      SendAncillaryBuffer,
      SendAncillaryMessage,
      SendFlags,
      SocketFlags,
      accept_with,
      recv,
      recvmsg,
      send,
      sendmsg,
   },
   process::{
      Pid,
      Signal,
      geteuid,
      kill_process_group,
   },
   pty::{
      OpenptFlags,
      grantpt,
      ioctl_tiocgptpeer,
      openpt,
      unlockpt,
   },
   termios::tcsetwinsize,
   time::Timespec,
};

use crate::{
   child::{
      become_account,
      exit_code,
   },
   session::winsize,
};

/// Most session bytes one packet carries.
pub const DATA_LIMIT: usize = 32 << 10;
/// Room for the largest packet.
pub const PACKET_LIMIT: usize = DATA_LIMIT + 32;
/// How long output may stay open after the command exits. A background
/// process that inherited it would otherwise hold the session open.
const EXIT_GRACE: Duration = Duration::from_millis(200);
/// How much more input the session accepts before the link hears of it.
const REPORT_STEP: u64 = 64 << 10;

/// Names the packet format. A holder outlives the server that started it,
/// so a newer server may find one that speaks another format. The first
/// two bytes of [`Packet::Attach`] and [`Packet::Attached`], the tag and
/// this number, are the one part that must never change.
const VERSION: u8 = 1;

/// Tag of [`Packet::Attach`].
const ATTACH: u8 = 1;
/// Tag of [`Packet::Attached`].
const ATTACHED: u8 = 2;
/// Tag of [`Packet::Data`].
const DATA: u8 = 3;
/// Tag of [`Packet::Resize`].
const RESIZE: u8 = 4;
/// Tag of [`Packet::Exit`].
const EXIT: u8 = 5;
/// Tag of [`Packet::Hangup`].
const HANGUP: u8 = 6;
/// Tag of [`Packet::Agent`].
const AGENT: u8 = 7;
/// Tag of [`Packet::Errors`].
const ERRORS: u8 = 8;
/// Tag of [`Packet::End`].
const END: u8 = 9;
/// Tag of [`Packet::Written`].
const WRITTEN: u8 = 10;
/// Tag of [`Packet::Received`].
const RECEIVED: u8 = 11;

/// One message between the network process and a holder.
pub enum Packet {
   /// Starts the flow of output after what the client already has.
   Attach {
      /// Output bytes the client has.
      received: u64,
      /// Standard error bytes the client has.
      errors:   u64,
   },
   /// The holder's answer to [`Packet::Attach`].
   Attached {
      /// Input bytes the holder has.
      taken:   u64,
      /// Output bytes the client lacks and the holder no longer keeps.
      skipped: u64,
      /// Whether the session runs on pipes and has a standard error.
      piped:   bool,
   },
   /// Session input, or output from the terminal or standard output.
   Data(Bytes),
   /// Standard error of a session on pipes.
   Errors(Bytes),
   /// The client's input ended.
   End,
   /// How many input bytes the session accepted so far.
   Written(u64),
   /// How much the client has, which the holder may forget.
   Received {
      /// Output bytes the client has.
      output: u64,
      /// Standard error bytes the client has.
      errors: u64,
   },
   /// The client's terminal changed size.
   Resize(Size),
   /// The session ended with this status. Nothing follows.
   Exit(u32),
   /// The client is done with the session.
   Hangup,
   /// A program in the session wants the client's SSH agent. Its socket
   /// comes along as a descriptor.
   Agent,
   /// What the other side sent first is in another version's format. A
   /// holder answers with this, which reads the same way to the server.
   Foreign,
}

impl Packet {
   /// The bytes of one packet.
   pub fn encode(&self) -> Vec<u8> {
      match *self {
         Self::Foreign => vec![ATTACHED, VERSION],
         Self::Attach { received, errors } => {
            [
               &[ATTACH, VERSION][..],
               &received.to_be_bytes(),
               &errors.to_be_bytes(),
            ]
            .concat()
         },
         Self::Attached {
            taken,
            skipped,
            piped,
         } => {
            [
               &[ATTACHED, VERSION][..],
               &taken.to_be_bytes(),
               &skipped.to_be_bytes(),
               &[u8::from(piped)],
            ]
            .concat()
         },
         Self::Data(ref bytes) => [&[DATA][..], bytes].concat(),
         Self::Errors(ref bytes) => [&[ERRORS][..], bytes].concat(),
         Self::End => vec![END],
         Self::Written(count) => [&[WRITTEN][..], &count.to_be_bytes()].concat(),
         Self::Received { output, errors } => {
            [
               &[RECEIVED][..],
               &output.to_be_bytes(),
               &errors.to_be_bytes(),
            ]
            .concat()
         },
         Self::Resize(size) => {
            [
               &[RESIZE][..],
               &size.columns.to_be_bytes(),
               &size.rows.to_be_bytes(),
            ]
            .concat()
         },
         Self::Exit(status) => [&[EXIT][..], &status.to_be_bytes()].concat(),
         Self::Hangup => vec![HANGUP],
         Self::Agent => vec![AGENT],
      }
   }

   /// Parses one packet.
   pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
      let (&tag, rest) = bytes.split_first().ok_or(Error::Truncated)?;
      let mut reader = Reader::new(rest);

      if matches!(tag, ATTACH | ATTACHED) && reader.byte()? != VERSION {
         return Ok(Self::Foreign);
      }

      let mut number =
         || Ok::<u64, Error>((u64::from(reader.u32()?) << 32) | u64::from(reader.u32()?));

      Ok(match tag {
         ATTACH => {
            Self::Attach {
               received: number()?,
               errors:   number()?,
            }
         },
         ATTACHED => {
            Self::Attached {
               taken:   number()?,
               skipped: number()?,
               piped:   reader.byte()? != 0,
            }
         },
         DATA => Self::Data(Bytes::copy_from_slice(rest)),
         ERRORS => Self::Errors(Bytes::copy_from_slice(rest)),
         END => Self::End,
         WRITTEN => Self::Written(number()?),
         RECEIVED => {
            Self::Received {
               output: number()?,
               errors: number()?,
            }
         },
         RESIZE => {
            let both = reader.u32()?;

            Self::Resize(Size {
               columns: u16::try_from(both >> 16).map_err(|_| Error::Frame)?,
               rows:    u16::try_from(both & 0xFFFF).map_err(|_| Error::Frame)?,
            })
         },
         EXIT => Self::Exit(reader.u32()?),
         HANGUP => Self::Hangup,
         AGENT => Self::Agent,
         _ => return Err(Error::Frame),
      })
   }

   /// Sends the packet, waiting for room unless the socket is non-blocking.
   pub fn send(&self, link: &OwnedFd) -> io::Result<()> {
      send(link, &self.encode(), SendFlags::NOSIGNAL)?;
      Ok(())
   }

   /// Sends `bytes` as a [`Packet::Data`] without copying them first.
   pub fn send_data(link: &OwnedFd, bytes: &[u8]) -> io::Result<()> {
      sendmsg(
         link,
         &[IoSlice::new(&[DATA]), IoSlice::new(bytes)],
         &mut SendAncillaryBuffer::default(),
         SendFlags::NOSIGNAL,
      )?;

      Ok(())
   }

   /// Waits for the next packet and the descriptor it may carry. `None`
   /// means the other side closed.
   pub fn receive(
      link: &OwnedFd,
      buffer: &mut [u8],
   ) -> io::Result<Option<(Self, Option<OwnedFd>)>> {
      let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(1))];
      let mut ancillary = RecvAncillaryBuffer::new(&mut space);

      let count = recvmsg(
         link,
         &mut [IoSliceMut::new(&mut *buffer)],
         &mut ancillary,
         RecvFlags::CMSG_CLOEXEC,
      )?
      .bytes;

      if count == 0 {
         return Ok(None);
      }

      let descriptor = ancillary
         .drain()
         .filter_map(|message| {
            match message {
               RecvAncillaryMessage::ScmRights(descriptors) => Some(descriptors),
               _ => None,
            }
         })
         .flatten()
         .next();

      Self::decode(&buffer[..count])
         .map(|packet| Some((packet, descriptor)))
         .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
   }
}

/// What one holder runs.
pub struct Hold {
   /// Account the session runs as.
   pub user:     String,
   /// The terminal to run on, or `None` for pipes.
   pub terminal: Option<Terminal>,
   /// The command, or `None` for a login shell.
   pub command:  Option<String>,
   /// What the client asked for when the key forces another command.
   pub original: Option<String>,
   /// Whether the session gets a socket to the client's SSH agent.
   pub agent:    bool,
}

/// The socket programs in the session open to reach the client's SSH agent.
/// Dropping it removes the socket and its directory.
struct AgentSocket {
   /// A directory only the account can enter.
   directory: PathBuf,
   /// Accepts those programs, once the holder runs as the account.
   listener:  Option<UnixListener>,
}

impl AgentSocket {
   /// Picks a directory name nobody can guess.
   fn new() -> Result<Self> {
      let mut random = [0; 8];
      SystemRandom::new()
         .fill(&mut random)
         .map_err(|_| report!("system random source failed"))?;

      Ok(Self {
         directory: env::temp_dir().join(format!("quicsh-{:016x}", u64::from_be_bytes(random))),
         listener:  None,
      })
   }

   /// Where the socket is.
   fn path(&self) -> PathBuf {
      self.directory.join("agent.sock")
   }

   /// Makes the directory and the socket.
   fn listen(&mut self) -> Result<()> {
      DirBuilder::new()
         .mode(0o700)
         .create(&self.directory)
         .with_context(|| format!("creating {}", self.directory.display()))?;

      let listener = UnixListener::bind(self.path()).context("binding the agent socket")?;
      listener.set_nonblocking(true)?;
      self.listener = Some(listener);

      Ok(())
   }
}

impl Drop for AgentSocket {
   fn drop(&mut self) {
      if self.listener.is_some() {
         let _ = fs::remove_file(self.path());
         let _ = fs::remove_dir(&self.directory);
      }
   }
}

/// One stream of session output.
struct Flow {
   /// Where the output comes from.
   source: OwnedFd,
   /// The output the client may lack.
   tail:   Tail,
   /// Whether the source has no more output.
   ended:  bool,
}

/// Names one of a session's output streams.
#[derive(Clone, Copy)]
enum Stream {
   /// The terminal, or standard output.
   Output,
   /// Standard error.
   Errors,
}

/// What each descriptor is ready for.
struct Ready {
   /// Accepts the network process.
   listener: PollFlags,
   /// The exit status pipe.
   status:   PollFlags,
   /// The session's input.
   input:    PollFlags,
   /// The terminal, or standard output.
   output:   PollFlags,
   /// Standard error.
   errors:   PollFlags,
   /// The network process.
   link:     PollFlags,
   /// Accepts programs that want the SSH agent.
   agent:    PollFlags,
}

/// A running session and its link to the network process.
struct Holder {
   /// Takes the session's input, until it is closed.
   input:    Option<OwnedFd>,
   /// The terminal, or standard output.
   output:   Flow,
   /// Standard error, for a session on pipes.
   errors:   Option<Flow>,
   /// Accepts the network process.
   listener: OwnedFd,
   /// Accepts programs that want the client's SSH agent.
   agent:    Option<AgentSocket>,
   /// Yields the exit status once, as four bytes.
   status:   File,
   /// The session's process group.
   group:    Pid,
   /// How many input bytes arrived.
   taken:    u64,
   /// How many input bytes the session accepted.
   written:  u64,
   /// The count of accepted bytes the link last heard.
   told:     u64,
   /// Input the session has not accepted yet.
   queue:    VecDeque<Bytes>,
   /// Whether the client's input ended.
   closing:  bool,
   /// The network process, while one is connected.
   link:     Option<OwnedFd>,
   /// Whether the link asked for output.
   attached: bool,
   /// Packets the link has not accepted yet.
   outbox:   VecDeque<Bytes>,
   /// When the last link went away.
   detached: Instant,
   /// Exit status and when it arrived.
   exited:   Option<(u32, Instant)>,
   /// Whether the link was told the exit status.
   reported: bool,
}

impl Holder {
   /// Forgets the link.
   fn detach(&mut self, now: Instant) {
      self.link = None;
      self.attached = false;
      self.reported = false;
      self.outbox.clear();
      self.detached = now;
   }

   /// Sends queued packets until the link would block.
   fn flush(&mut self) {
      while let (Some(link), Some(packet)) = (self.link.as_ref(), self.outbox.front()) {
         match send(link, packet, SendFlags::NOSIGNAL | SendFlags::DONTWAIT) {
            Ok(_) => {
               self.outbox.pop_front();
            },
            Err(Errno::WOULDBLOCK) => return,
            // A network process that hung up closed the link right after
            // saying so, and that packet is still to be read.
            Err(_) => {
               self.attached = false;
               self.outbox.clear();
            },
         }
      }
   }

   /// Queues a packet for the link.
   fn push(&mut self, packet: &Packet) {
      self.outbox.push_back(packet.encode().into());
      self.flush();
   }

   /// Hands a program that wants the SSH agent to the link. Without a link
   /// that listens, the program sees its connection close.
   fn offer(&self) {
      let accepting = self
         .agent
         .as_ref()
         .and_then(|agent| agent.listener.as_ref());

      let Some(Ok((socket, _))) = accepting.map(UnixListener::accept) else {
         return;
      };

      let Some(link) = self.link.as_ref().filter(|_| self.attached) else {
         return;
      };

      let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(1))];
      let mut ancillary = SendAncillaryBuffer::new(&mut space);
      let descriptors = [socket.as_fd()];
      ancillary.push(SendAncillaryMessage::ScmRights(&descriptors));

      let _ = sendmsg(
         link,
         &[IoSlice::new(&Packet::Agent.encode())],
         &mut ancillary,
         SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
      );
   }

   /// Answers a link that asked for output with the counts it needs and the
   /// output its client lacks.
   fn attach(&mut self, received: u64, errors: u64) {
      self.attached = true;
      self.told = self.written;

      let answer = Packet::Attached {
         taken:   self.taken,
         skipped: self.output.tail.dropped(received),
         piped:   self.errors.is_some(),
      };

      let mut packets = vec![answer.encode(), Packet::Written(self.written).encode()];

      for chunk in self.output.tail.since(received) {
         packets.push([&[DATA][..], &chunk].concat());
      }

      if let Some(ref flow) = self.errors {
         for chunk in flow.tail.since(errors) {
            packets.push([&[ERRORS][..], &chunk].concat());
         }
      }

      self.outbox.extend(packets.into_iter().map(Bytes::from));
      self.flush();
   }

   /// Handles everything the link sent. Breaks when the client hung up.
   fn receive(&mut self, now: Instant, buffer: &mut [u8]) -> ControlFlow<()> {
      while let Some(ref link) = self.link {
         let packet = match recv(link, &mut *buffer, RecvFlags::DONTWAIT) {
            Ok((count, _)) if count > 0 => Packet::decode(&buffer[..count]).ok(),
            Err(Errno::WOULDBLOCK) => return ControlFlow::Continue(()),
            Ok(_) | Err(_) => None,
         };

         match packet {
            Some(Packet::Attach { received, errors }) => self.attach(received, errors),
            Some(Packet::Data(bytes)) => {
               self.taken += bytes.len() as u64;
               self.queue.push_back(bytes);
            },
            // A terminal has no end of input to pass on.
            Some(Packet::End) => self.closing = self.errors.is_some(),
            Some(Packet::Received { output, errors }) => {
               self.output.tail.release(output);

               if let Some(ref mut flow) = self.errors {
                  flow.tail.release(errors);
               }
            },
            Some(Packet::Resize(size)) => {
               if self.errors.is_none() {
                  let _ = tcsetwinsize(&self.output.source, winsize(size));
               }
            },
            Some(Packet::Hangup) => return ControlFlow::Break(()),
            Some(Packet::Foreign) => {
               let _ = Packet::Foreign.send(link);
               self.detach(now);
            },
            Some(
               Packet::Attached { .. }
               | Packet::Errors(_)
               | Packet::Written(_)
               | Packet::Exit(_)
               | Packet::Agent,
            )
            | None => self.detach(now),
         }
      }

      ControlFlow::Continue(())
   }

   /// Gives queued input to the session and tells the link how far it got.
   /// Input for a session that closed its end counts as accepted, so that
   /// the sender never waits for it.
   fn feed(&mut self) {
      while let (Some(input), Some(chunk)) = (self.input.as_ref(), self.queue.front_mut()) {
         match write(input, chunk) {
            Ok(count) => {
               self.written += count as u64;
               chunk.advance(count);

               if chunk.is_empty() {
                  self.queue.pop_front();
               }
            },
            Err(Errno::WOULDBLOCK) => break,
            Err(_) => self.input = None,
         }
      }

      if self.input.is_none() {
         self.queue.clear();
         self.written = self.taken;
      } else if self.closing && self.queue.is_empty() {
         self.input = None;
      }

      let due = self.queue.is_empty() || self.written - self.told >= REPORT_STEP;

      if self.attached && self.written != self.told && due {
         self.told = self.written;
         self.push(&Packet::Written(self.written));
      }
   }

   /// Reads one chunk of `stream`, keeps it and passes it to the link. An
   /// `overdue` stream with nothing to read has ended.
   fn collect(&mut self, stream: Stream, overdue: bool, buffer: &mut [u8]) {
      let (tag, chosen) = match stream {
         Stream::Output => (DATA, Some(&mut self.output)),
         Stream::Errors => (ERRORS, self.errors.as_mut()),
      };

      let Some(flow) = chosen.filter(|open| !open.ended) else {
         return;
      };

      buffer[0] = tag;

      match read(&flow.source, &mut buffer[1..=DATA_LIMIT]) {
         Ok(0) => flow.ended = true,
         Ok(count) => {
            let packet = Bytes::copy_from_slice(&buffer[..=count]);
            flow.tail.record(packet.slice(1..));

            if self.attached {
               self.outbox.push_back(packet);
               self.flush();
            }
         },
         Err(Errno::WOULDBLOCK) => flow.ended = overdue,
         // A terminal whose other side closed fails with EIO, which is its
         // end of output.
         Err(_) => flow.ended = true,
      }
   }

   /// Whether every output stream has ended.
   fn ended(&self) -> bool {
      self.output.ended && self.errors.as_ref().is_none_or(|flow| flow.ended)
   }

   /// Whether output is read now. With a link, it is read only when the
   /// link takes it, so a full link makes the program wait. Without one, a
   /// terminal's output goes on into what is kept, and a pipe's waits,
   /// because none of it may be dropped.
   #[expect(
      clippy::missing_const_for_fn,
      reason = "VecDeque::is_empty is const from Rust 1.101, and stable 1.100 rejects it"
   )]
   fn reading(&self) -> bool {
      if self.link.is_some() {
         self.attached && self.outbox.is_empty()
      } else {
         self.errors.is_none()
      }
   }

   /// Sleeps until something needs handling.
   fn wait(&self, now: Instant, reading: bool) -> Result<Ready> {
      let mut sending = PollFlags::IN;
      sending.set(PollFlags::OUT, !self.outbox.is_empty());

      let deadline = [
         self.link.is_none().then(|| self.detached + DETACH_LIMIT),
         self
            .exited
            .map(|(_, at)| at + EXIT_GRACE)
            .filter(|&at| now < at && !self.ended()),
      ]
      .into_iter()
      .flatten()
      .min();

      let timeout = deadline.map(|at| {
         let wait = at.saturating_duration_since(now);

         Timespec {
            tv_sec:  i64::try_from(wait.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: wait.subsec_nanos().into(),
         }
      });

      // A descriptor that is not wanted stays out of the set, because the
      // kernel reports a hangup on it regardless and the loop would spin.
      let mut fds = vec![PollFd::new(&self.listener, PollFlags::IN)];
      let watched = [
         self
            .exited
            .is_none()
            .then(|| PollFd::new(&self.status, PollFlags::IN)),
         self
            .input
            .as_ref()
            .filter(|_| !self.queue.is_empty())
            .map(|input| PollFd::new(input, PollFlags::OUT)),
         (reading && !self.output.ended).then(|| PollFd::new(&self.output.source, PollFlags::IN)),
         self
            .errors
            .as_ref()
            .filter(|flow| reading && !flow.ended)
            .map(|flow| PollFd::new(&flow.source, PollFlags::IN)),
         self.link.as_ref().map(|link| PollFd::new(link, sending)),
         self
            .agent
            .as_ref()
            .and_then(|agent| agent.listener.as_ref())
            .map(|listener| PollFd::new(listener, PollFlags::IN)),
      ]
      .map(|entry| {
         entry.map(|fd| {
            fds.push(fd);
            fds.len() - 1
         })
      });

      match poll(&mut fds, timeout.as_ref()) {
         Ok(_) | Err(Errno::INTR) => {},
         Err(errno) => return Err(errno).context("waiting for the session").erase(),
      }

      let ready = fds.iter().map(PollFd::revents).collect::<Vec<PollFlags>>();
      drop(fds);

      let [status, input, output, errors, link, agent] =
         watched.map(|index| index.map_or(PollFlags::empty(), |at| ready[at]));

      Ok(Ready {
         listener: ready[0],
         status,
         input,
         output,
         errors,
         link,
         agent,
      })
   }

   /// Waits for one thing to happen and handles it. Breaks when the session
   /// is over for good, which is when the client hung up or stayed away too
   /// long. A session that ended stays until then, because only the client
   /// knows whether it got the last output.
   fn turn(&mut self, buffer: &mut [u8]) -> Result<ControlFlow<()>> {
      let mut now = Instant::now();

      if let Some((status, _)) = self.exited
         && self.ended()
         && self.attached
         && !self.reported
      {
         self.reported = true;
         self.push(&Packet::Exit(status));
      }

      if self.link.is_none() && now >= self.detached + DETACH_LIMIT {
         return Ok(ControlFlow::Break(()));
      }

      let reading = self.reading();
      let ready = self.wait(now, reading)?;
      now = Instant::now();

      if !ready.agent.is_empty() {
         self.offer();
      }

      if !ready.listener.is_empty() {
         let accepted = accept_with(&self.listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)
            .context("accepting the network process")?;

         self.detach(now);
         self.link = Some(accepted);
      } else if !ready.link.is_empty() {
         if self.receive(now, buffer).is_break() {
            return Ok(ControlFlow::Break(()));
         }

         self.flush();
         self.feed();
      }

      if !ready.status.is_empty() {
         let mut code = [0; 4];
         let known = self.status.read_exact(&mut code).is_ok();

         self.exited = Some((if known { u32::from_be_bytes(code) } else { 255 }, now));
      }

      if !ready.input.is_empty() {
         self.feed();
      }

      // A background process that inherited the output may hold it open
      // after the command exits, so it then ends once nothing is left in it.
      let overdue = self.exited.is_some_and(|(_, at)| now >= at + EXIT_GRACE);

      for (stream, flags) in [
         (Stream::Output, ready.output),
         (Stream::Errors, ready.errors),
      ] {
         if reading && (overdue || !flags.is_empty()) {
            self.collect(stream, overdue, buffer);
         }
      }

      Ok(ControlFlow::Continue(()))
   }
}

/// Opens a terminal of `size` and returns its two sides, the session's last.
fn open_terminal(size: Size, account: &Account) -> Result<(OwnedFd, OwnedFd)> {
   let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
   let master = openpt(flags).context("opening a terminal")?;
   grantpt(&master)?;
   unlockpt(&master)?;
   tcsetwinsize(&master, winsize(size))?;

   let slave = ioctl_tiocgptpeer(&master, flags)?;

   // The account owns the terminal device, because programs such as tmux
   // open it by path.
   if geteuid().is_root() {
      fchown(&slave, Some(account.uid), None)?;
   }

   Ok((master, slave))
}

impl Hold {
   /// Starts the session on a new terminal or on pipes and serves it until
   /// it is over. Standard input is the listening socket.
   pub fn run(&self) -> Result<()> {
      let listener = io::stdin().as_fd().try_clone_to_owned()?;
      let account = Account::lookup(&self.user)?.context("account vanished after login")?;

      let mut command = Command::new(env::current_exe()?);
      command.arg("session").arg(&self.user);

      let mut agent = self.agent.then(AgentSocket::new).transpose()?;

      if let Some(ref socket) = agent {
         command.arg("--agent-socket").arg(socket.path());
      }

      if let Some(ref text) = self.command {
         command.arg("--command").arg(text);
      }

      if let Some(ref text) = self.original {
         command.arg("--original-command").arg(text);
      }

      let master = if let Some(ref terminal) = self.terminal {
         let (master, slave) = open_terminal(terminal.size, &account)?;

         command
            .arg("--term")
            .arg(&terminal.name)
            .stdin(slave.try_clone()?)
            .stdout(slave.try_clone()?)
            .stderr(slave);

         Some(master)
      } else {
         command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

         None
      };

      let mut child = command.spawn().context("starting the session process")?;
      let group = Pid::from_child(&child);

      let (input, output, errors) = if let Some(terminal) = master {
         (terminal.try_clone()?, terminal, None)
      } else {
         let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());

         let (Some(input), Some(output), Some(errors)) = pipes else {
            bail!("the session process has no pipes");
         };

         (input.into(), output.into(), Some(OwnedFd::from(errors)))
      };

      // The copies of the terminal's child side live in `command`, and the
      // terminal reports end of output only once they are closed.
      drop(command);

      // Everything from here on handles bytes a client chose, so it runs
      // without privileges.
      become_account(&account)?;

      if let Some(ref mut socket) = agent {
         socket.listen()?;
      }

      let (status, mut report) = io::pipe()?;

      thread::spawn(move || {
         let code = child.wait().map_or(255, exit_code);
         let _ = report.write_all(&code.to_be_bytes());
      });

      for descriptor in [Some(&input), Some(&output), errors.as_ref()]
         .into_iter()
         .flatten()
      {
         ioctl_fionbio(descriptor, true)?;
      }

      let flow = |source, piped: bool| {
         Flow {
            source,
            tail: if piped {
               Tail::exact()
            } else {
               Tail::default()
            },
            ended: false,
         }
      };

      let piped = errors.is_some();

      let mut holder = Holder {
         input: Some(input),
         output: flow(output, piped),
         errors: errors.map(|source| flow(source, piped)),
         listener,
         agent,
         status: File::from(OwnedFd::from(status)),
         group,
         taken: 0,
         written: 0,
         told: 0,
         queue: VecDeque::new(),
         closing: false,
         link: None,
         attached: false,
         outbox: VecDeque::new(),
         detached: Instant::now(),
         exited: None,
         reported: false,
      };

      let mut buffer = vec![0; PACKET_LIMIT];

      while holder.turn(&mut buffer)?.is_continue() {}

      // The session leads its own process group, so this reaches the command
      // and its foreground children.
      if holder.exited.is_none() {
         let _ = kill_process_group(holder.group, Signal::HUP);
      }

      Ok(())
   }
}
