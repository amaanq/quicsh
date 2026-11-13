//! The process that owns one terminal session, so that the session outlives
//! the server.
//!
//! - The monitor starts a holder for each terminal session and hands it a
//!   listening socket in a directory only the monitor can enter.
//! - The holder opens the terminal, starts the session and then becomes the
//!   session's account. It keeps the newest output and counts the input, which
//!   is what a client needs to continue after its connection or the server went
//!   away.
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
   process::Command,
   thread,
   time::{
      Duration,
      Instant,
   },
};

use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   report,
};
use quicsh::{
   auth::Account,
   control::{
      DETACH_LIMIT,
      Size,
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
/// How long output may keep flowing after the command exits. A background
/// process that inherited the terminal would otherwise hold the session open.
const EXIT_GRACE: Duration = Duration::from_millis(200);

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

/// One message between the network process and a holder.
pub enum Packet {
   /// Starts the flow of output. `received` is how much output the client
   /// already has.
   Attach {
      /// Output bytes the client has.
      received: u64,
   },
   /// The holder's answer to [`Packet::Attach`].
   Attached {
      /// Input bytes the holder has.
      taken:   u64,
      /// Output bytes the client lacks and the holder no longer keeps.
      skipped: u64,
   },
   /// Terminal input or output.
   Data(Vec<u8>),
   /// The client's terminal changed size.
   Resize(Size),
   /// The session ended with this status. Nothing follows.
   Exit(u32),
   /// The client is done with the session.
   Hangup,
   /// A program in the session wants the client's SSH agent. Its socket
   /// comes along as a descriptor.
   Agent,
}

impl Packet {
   /// The bytes of one packet.
   pub fn encode(&self) -> Vec<u8> {
      match *self {
         Self::Attach { received } => [&[ATTACH][..], &received.to_be_bytes()].concat(),
         Self::Attached { taken, skipped } => {
            [
               &[ATTACHED][..],
               &taken.to_be_bytes(),
               &skipped.to_be_bytes(),
            ]
            .concat()
         },
         Self::Data(ref bytes) => [&[DATA][..], bytes].concat(),
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
      let mut number =
         || Ok::<u64, Error>((u64::from(reader.u32()?) << 32) | u64::from(reader.u32()?));

      Ok(match tag {
         ATTACH => {
            Self::Attach {
               received: number()?,
            }
         },
         ATTACHED => {
            Self::Attached {
               taken:   number()?,
               skipped: number()?,
            }
         },
         DATA => Self::Data(rest.to_vec()),
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
   /// The client's `TERM`.
   pub terminal: String,
   /// The command, or `None` for a login shell.
   pub command:  Option<String>,
   /// What the client asked for when the key forces another command.
   pub original: Option<String>,
   /// Whether the session gets a socket to the client's SSH agent.
   pub agent:    bool,
   /// The terminal's first size.
   pub size:     Size,
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

/// A running session and its link to the network process.
struct Holder {
   /// The terminal.
   master:   OwnedFd,
   /// Accepts the network process.
   listener: OwnedFd,
   /// Accepts programs that want the client's SSH agent.
   agent:    Option<AgentSocket>,
   /// Yields the exit status once, as four bytes.
   status:   File,
   /// The session's process group.
   group:    Pid,
   /// The newest output.
   tail:     Tail,
   /// How many input bytes arrived.
   taken:    u64,
   /// Input the terminal has not accepted yet.
   input:    Vec<u8>,
   /// The network process, while one is connected.
   link:     Option<OwnedFd>,
   /// Whether the link asked for output.
   attached: bool,
   /// Packets the link has not accepted yet.
   outbox:   VecDeque<Vec<u8>>,
   /// When the last link went away.
   detached: Instant,
   /// Exit status and when it arrived.
   exited:   Option<(u32, Instant)>,
   /// Whether the terminal has no more output.
   ended:    bool,
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
   fn flush(&mut self, now: Instant) {
      while let (Some(link), Some(packet)) = (self.link.as_ref(), self.outbox.front()) {
         match send(link, packet, SendFlags::NOSIGNAL | SendFlags::DONTWAIT) {
            Ok(_) => {
               self.outbox.pop_front();
            },
            Err(Errno::WOULDBLOCK) => return,
            Err(_) => self.detach(now),
         }
      }
   }

   /// Queues a packet for the link.
   fn push(&mut self, now: Instant, packet: &Packet) {
      self.outbox.push_back(packet.encode());
      self.flush(now);
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

   /// Handles everything the link sent. Breaks when the client hung up.
   fn receive(&mut self, now: Instant, buffer: &mut [u8]) -> ControlFlow<()> {
      while let Some(ref link) = self.link {
         let packet = match recv(link, &mut *buffer, RecvFlags::DONTWAIT) {
            Ok((count, _)) if count > 0 => Packet::decode(&buffer[..count]).ok(),
            Err(Errno::WOULDBLOCK) => return ControlFlow::Continue(()),
            Ok(_) | Err(_) => None,
         };

         match packet {
            Some(Packet::Attach { received }) => {
               self.attached = true;

               let answer = Packet::Attached {
                  taken:   self.taken,
                  skipped: self.tail.dropped(received),
               };
               self.push(now, &answer);

               for chunk in self.tail.since(received).chunks(DATA_LIMIT) {
                  self.push(now, &Packet::Data(chunk.to_vec()));
               }
            },
            Some(Packet::Data(bytes)) => {
               self.taken += bytes.len() as u64;
               self.input.extend_from_slice(&bytes);
            },
            Some(Packet::Resize(size)) => {
               let _ = tcsetwinsize(&self.master, winsize(size));
            },
            Some(Packet::Hangup) => return ControlFlow::Break(()),
            Some(Packet::Attached { .. } | Packet::Exit(_) | Packet::Agent) | None => {
               self.detach(now);
            },
         }
      }

      ControlFlow::Continue(())
   }

   /// Whether output is read now. It is read only when it has somewhere to
   /// go, which is the link when one is attached and the tail when none is
   /// connected. A full link therefore makes the program wait, as a slow
   /// terminal would.
   #[allow(
      clippy::missing_const_for_fn,
      reason = "VecDeque::is_empty is const from Rust 1.101, and stable 1.100 rejects it"
   )]
   fn reading(&self) -> bool {
      !self.ended
         && if self.link.is_some() {
            self.attached && self.outbox.is_empty()
         } else {
            true
         }
   }

   /// Sleeps until something needs handling. Returns what the listener, the
   /// status pipe, the terminal, the link and the agent socket are ready for.
   fn wait(&self, now: Instant) -> Result<[PollFlags; 5]> {
      let reading = self.reading();

      let mut terminal = PollFlags::empty();
      terminal.set(PollFlags::IN, reading);
      terminal.set(PollFlags::OUT, !self.input.is_empty());

      let mut sending = PollFlags::IN;
      sending.set(PollFlags::OUT, !self.outbox.is_empty());

      let deadline = [
         self.link.is_none().then(|| self.detached + DETACH_LIMIT),
         self
            .exited
            .filter(|_| !self.ended)
            .map(|(_, at)| at + EXIT_GRACE),
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
         (!terminal.is_empty()).then(|| PollFd::new(&self.master, terminal)),
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

      let [status, master, link, agent] =
         watched.map(|index| index.map_or(PollFlags::empty(), |at| ready[at]));

      Ok([ready[0], status, master, link, agent])
   }

   /// Waits for one thing to happen and handles it. Breaks when the session
   /// is over for good.
   fn turn(&mut self, buffer: &mut [u8]) -> Result<ControlFlow<()>> {
      let mut now = Instant::now();

      if let Some((status, at)) = self.exited {
         self.ended |= now >= at + EXIT_GRACE;

         if self.ended && self.attached && !self.reported {
            self.reported = true;
            self.push(now, &Packet::Exit(status));
         }

         if self.reported && self.outbox.is_empty() {
            return Ok(ControlFlow::Break(()));
         }
      }

      if self.link.is_none() && now >= self.detached + DETACH_LIMIT {
         return Ok(ControlFlow::Break(()));
      }

      let reading = self.reading();
      let [listener, status, master, link, agent] = self.wait(now)?;
      now = Instant::now();

      if !agent.is_empty() {
         self.offer();
      }

      if !listener.is_empty() {
         let accepted = accept_with(&self.listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)
            .context("accepting the network process")?;

         self.detach(now);
         self.link = Some(accepted);
      } else if !link.is_empty() {
         if self.receive(now, buffer).is_break() {
            return Ok(ControlFlow::Break(()));
         }

         self.flush(now);
      }

      if !status.is_empty() {
         let mut code = [0; 4];
         let known = self.status.read_exact(&mut code).is_ok();

         self.exited = Some((if known { u32::from_be_bytes(code) } else { 255 }, now));
      }

      if master.intersects(PollFlags::OUT) {
         match write(&self.master, &self.input) {
            Ok(written) => {
               self.input.drain(..written);
            },
            Err(Errno::WOULDBLOCK) => {},
            Err(_) => self.input.clear(),
         }
      }

      if reading && !master.difference(PollFlags::OUT).is_empty() {
         match read(&self.master, &mut buffer[..DATA_LIMIT]) {
            Ok(0) => self.ended = true,
            Ok(count) => {
               let bytes = &buffer[..count];
               self.tail.record(bytes);

               if self.attached {
                  self.push(now, &Packet::Data(bytes.to_vec()));
               }
            },
            Err(Errno::WOULDBLOCK) => {},
            // A terminal whose other side closed fails with EIO, which is its
            // end of output.
            Err(_) => self.ended = true,
         }
      }

      Ok(ControlFlow::Continue(()))
   }
}

impl Hold {
   /// Starts the session on a new terminal and serves it until it is over.
   /// Standard input is the listening socket.
   pub fn run(&self) -> Result<()> {
      let listener = io::stdin().as_fd().try_clone_to_owned()?;
      let account = Account::lookup(&self.user)?.context("account vanished after login")?;

      let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
      let master = openpt(flags).context("opening a terminal")?;
      grantpt(&master)?;
      unlockpt(&master)?;
      tcsetwinsize(&master, winsize(self.size))?;

      let slave = ioctl_tiocgptpeer(&master, flags)?;

      // The account owns the terminal device, because programs such as tmux
      // open it by path.
      if geteuid().is_root() {
         fchown(&slave, Some(account.uid), None)?;
      }

      let mut command = Command::new(env::current_exe()?);
      command
         .arg("session")
         .arg(&self.user)
         .arg("--term")
         .arg(&self.terminal);

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

      command
         .stdin(slave.try_clone()?)
         .stdout(slave.try_clone()?)
         .stderr(slave);

      let mut child = command.spawn().context("starting the session process")?;
      let group = Pid::from_child(&child);

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

      ioctl_fionbio(&master, true)?;

      let mut holder = Holder {
         master,
         listener,
         agent,
         status: File::from(OwnedFd::from(status)),
         group,
         tail: Tail::default(),
         taken: 0,
         input: Vec::new(),
         link: None,
         attached: false,
         outbox: VecDeque::new(),
         detached: Instant::now(),
         exited: None,
         ended: false,
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
