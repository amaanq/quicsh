//! The socket through which one `qsh` shares its connection with later
//! ones, as OpenSSH does with `ControlMaster`.
//!
//! - The `qsh` that holds the connection listens on a Unix socket. A later one
//!   connects, sends what it wants to run and hands over its standard streams,
//!   which the holder then reads and writes itself.
//! - The later one waits for a [`Notice`] with the exit status. Closing the
//!   socket gives the session up.

use std::{
   fs::{
      self,
      File,
   },
   io,
   os::fd::{
      AsFd as _,
      OwnedFd,
   },
   path::Path,
   process,
   sync::{
      Arc,
      mpsc::{
         Receiver,
         Sender,
         channel,
      },
   },
   thread,
};

use misstep::{
   Result,
   ResultExt as _,
   bail,
};
use quicsh::{
   control::{
      Deframer,
      Message,
      Open,
   },
   pipe::{
      Waker,
      accept as accept_socket,
      receive_framed,
      send_framed,
      socket,
   },
};
use rustix::{
   event::{
      PollFd,
      PollFlags,
      poll,
   },
   fs::Mode,
   io::Errno,
   net::{
      AddressFamily,
      SocketAddrUnix,
      SocketType,
      bind,
      connect as connect_socket,
      listen as listen_socket,
   },
   process::umask,
};

use crate::{
   channel::{
      RawMode,
      Streams,
   },
   forward::{
      Destination,
      Inbound,
   },
};

/// Largest message on the socket.
const MAX_MESSAGE: usize = 128 << 10;
/// Connections that may wait to be accepted.
const BACKLOG: i32 = 16;

/// Tag of a request for a session.
const OPEN: u8 = 1;
/// Tag of the question whether the holder runs.
const CHECK: u8 = 2;
/// Tag of the request that the holder exits once its sessions are over.
const STOP: u8 = 3;
/// Tag of the request that the holder ends its sessions and exits.
const END: u8 = 4;

/// Tag of a connection that the holder should forward, which comes with
/// where the server connects it to.
const FORWARD: u8 = 5;
/// Marks a [`Destination::Tcp`] in such a request.
const TCP: u8 = 0;
/// Marks a [`Destination::Unix`] in such a request.
const UNIX: u8 = 1;

/// Tag of [`Notice::Exit`].
const EXIT: u8 = 1;
/// Tag of [`Notice::Lost`].
const LOST: u8 = 2;
/// Tag of [`Notice::Resumed`].
const RESUMED: u8 = 3;

/// What the holder of the connection tells a `qsh` that shares it.
#[derive(Clone, Copy)]
pub enum Notice {
   /// The session ended with this status.
   Exit(u32),
   /// The connection died and the holder is dialing again. A terminal
   /// leaves raw mode meanwhile.
   Lost,
   /// The session goes on.
   Resumed,
}

impl Notice {
   /// Sends the notice. A peer that went away misses it.
   pub fn send(self, socket: &OwnedFd) {
      let bytes = match self {
         Self::Exit(status) => [&[EXIT][..], &status.to_be_bytes()].concat(),
         Self::Lost => vec![LOST],
         Self::Resumed => vec![RESUMED],
      };

      let _ = send_framed(socket, &bytes, &[]);
   }

   /// Parses one notice.
   fn decode(bytes: &[u8]) -> Option<Self> {
      match bytes.split_first()? {
         (&EXIT, rest) => Some(Self::Exit(u32::from_be_bytes(rest.try_into().ok()?))),
         (&LOST, _) => Some(Self::Lost),
         (&RESUMED, _) => Some(Self::Resumed),
         _ => None,
      }
   }
}

/// What reaches the holder's event loop from its socket.
pub enum Arrival {
   /// A `qsh` wants a session on the streams it handed over.
   Open {
      /// Names the `qsh` in a later [`Arrival::Closed`].
      peer:   u64,
      /// What to run.
      open:   Open,
      /// Where it runs.
      stdio:  Streams,
      /// Takes the [`Notice`]s about the session.
      socket: OwnedFd,
   },
   /// A `qsh` went away, and its session with it.
   Closed {
      /// The number from [`Arrival::Open`].
      peer: u64,
   },
   /// The holder should exit once its sessions are over.
   Stop,
   /// The holder should end its sessions and exit.
   End,
}

/// Makes the socket at `path`, which only this user may connect to.
pub fn listen(path: &Path) -> Result<OwnedFd> {
   let socket = socket(AddressFamily::UNIX, SocketType::STREAM)?;

   let address = SocketAddrUnix::new(path)?;

   // The mask is the one way to make the socket file private from the
   // start, and no other thread makes files yet.
   let saved = umask(Mode::from_raw_mode(0o177));
   let bound = bind(&socket, &address);
   umask(saved);

   bound.with_context(|| format!("binding {}", path.display()))?;
   listen_socket(&socket, BACKLOG)?;

   Ok(socket)
}

/// Connects to the holder that listens at `path`. A socket file that
/// nobody listens on any more is removed.
pub fn connect(path: &Path) -> io::Result<OwnedFd> {
   let socket = socket(AddressFamily::UNIX, SocketType::STREAM)?;

   match connect_socket(&socket, &SocketAddrUnix::new(path)?) {
      Ok(()) => Ok(socket),
      Err(Errno::CONNREFUSED) => {
         let _ = fs::remove_file(path);
         Err(Errno::CONNREFUSED.into())
      },
      Err(errno) => Err(errno.into()),
   }
}

/// Hands the holder at `path` a connection that a listener of this
/// process accepted.
pub fn forward(path: &Path, inbound: &Inbound) -> io::Result<()> {
   let mut bytes = vec![FORWARD];

   match inbound.destination {
      Destination::Tcp { ref host, port } => {
         bytes.push(TCP);
         bytes.extend_from_slice(&port.to_be_bytes());
         bytes.extend_from_slice(host.as_bytes());
      },
      Destination::Unix(ref file) => {
         bytes.push(UNIX);
         bytes.extend_from_slice(file.as_bytes());
      },
   }

   send_framed(&connect(path)?, &bytes, &[inbound.socket.as_fd()])
}

/// Parses where a forwarded connection goes.
fn destination(bytes: &[u8]) -> Option<Destination> {
   let text = |name: &[u8]| String::from_utf8(name.to_vec()).ok();

   match *bytes {
      [TCP, high, low, ref host @ ..] => {
         Some(Destination::Tcp {
            host: text(host)?,
            port: u16::from_be_bytes([high, low]),
         })
      },
      [UNIX, ref file @ ..] => text(file).map(Destination::Unix),
      _ => None,
   }
}

/// Serves one `qsh` that connected to the holder's socket. Connections to
/// forward go to `forwards`.
fn serve(
   socket: &OwnedFd,
   peer: u64,
   arrivals: &Sender<Arrival>,
   forwards: &Sender<Inbound>,
   waker: &Waker,
) {
   let Ok(Some((bytes, descriptors))) = receive_framed(socket, MAX_MESSAGE) else {
      return;
   };

   match bytes.split_first() {
      Some((&CHECK, _)) => {
         let _ = send_framed(socket, &process::id().to_be_bytes(), &[]);
      },
      Some((&STOP, _)) => {
         let _ = arrivals.send(Arrival::Stop);
         waker.wake();
      },
      Some((&END, _)) => {
         let _ = arrivals.send(Arrival::End);
         waker.wake();
      },
      Some((&FORWARD, rest)) => {
         let (Some(target), Ok([accepted])) =
            (destination(rest), <[OwnedFd; 1]>::try_from(descriptors))
         else {
            return;
         };

         let lent = Inbound {
            socket:      accepted,
            destination: target,
         };

         if forwards.send(lent).is_ok() {
            waker.wake();
         }
      },
      Some((&OPEN, frame)) => {
         let mut deframer = Deframer::default();
         deframer.push(frame);

         let (Ok(Some(Message::Open(open))), Ok([input, output, errors]), Ok(answers)) = (
            deframer.pop(),
            <[OwnedFd; 3]>::try_from(descriptors),
            socket.try_clone(),
         ) else {
            return;
         };

         let stdio = Streams {
            input:  File::from(input),
            output: File::from(output),
            errors: File::from(errors),
         };

         let opened = Arrival::Open {
            peer,
            open,
            stdio,
            socket: answers,
         };

         if arrivals.send(opened).is_err() {
            return;
         }

         waker.wake();

         // Nothing more is expected, so this returns when the peer is gone.
         let _ = receive_framed(socket, MAX_MESSAGE);
         let _ = arrivals.send(Arrival::Closed { peer });
         waker.wake();
      },
      _ => {},
   }
}

/// Accepts every `qsh` that connects to `listener` on threads, and yields
/// what they ask for. `waker` is woken for each [`Arrival`] and for each
/// connection that goes to `forwards`.
pub fn accept(
   listener: OwnedFd,
   waker: &Arc<Waker>,
   forwards: &Sender<Inbound>,
) -> Receiver<Arrival> {
   let (arrivals, receiver) = channel();
   let signal = Arc::clone(waker);
   let lent = forwards.clone();

   thread::spawn(move || {
      for peer in 0.. {
         let Ok(socket) = accept_socket(&listener) else {
            break;
         };

         let sender = arrivals.clone();
         let lender = lent.clone();
         let notifier = Arc::clone(&signal);

         thread::spawn(move || serve(&socket, peer, &sender, &lender, &notifier));
      }
   });

   receiver
}

/// Asks the holder behind `socket` for a session on this process's standard
/// streams.
pub fn open(socket: &OwnedFd, request: Open) -> io::Result<()> {
   let mut bytes = vec![OPEN];
   bytes.extend_from_slice(&Message::Open(request).encode());

   let (input, output, errors) = (io::stdin(), io::stdout(), io::stderr());
   send_framed(socket, &bytes, &[
      input.as_fd(),
      output.as_fd(),
      errors.as_fd(),
   ])
}

/// Waits for the session behind `socket` to end and returns its status.
/// `interactive` says that this process's terminal is in raw mode while the
/// session runs, and a signal on `signals` gives the session up.
pub fn wait(socket: &OwnedFd, signals: &File, interactive: bool) -> Result<u32> {
   let mut raw = interactive.then(RawMode::enable).transpose()?;

   loop {
      let mut fds = [
         PollFd::new(socket, PollFlags::IN),
         PollFd::new(signals, PollFlags::IN),
      ];

      match poll(&mut fds, None) {
         Ok(_) => {},
         Err(Errno::INTR) => continue,
         Err(errno) => return Err(errno).context("waiting for the session").erase(),
      }

      if !fds[1].revents().is_empty() {
         return Ok(255);
      }

      let Some((bytes, _)) = receive_framed(socket, MAX_MESSAGE)? else {
         drop(raw);
         bail!("the shared connection ended");
      };

      match Notice::decode(&bytes) {
         Some(Notice::Exit(status)) => return Ok(status),
         Some(Notice::Lost) => raw = None,
         // A second guard would save the raw mode as the one to restore,
         // and the first would put the terminal back as it is dropped.
         Some(Notice::Resumed) if interactive && raw.is_none() => {
            raw = Some(RawMode::enable()?);
         },
         Some(Notice::Resumed) | None => {},
      }
   }
}

/// Asks the holder at `path` for its process number.
pub fn check(path: &Path) -> Result<u32> {
   let socket =
      connect(path).with_context(|| format!("no shared connection at {}", path.display()))?;
   send_framed(&socket, &[CHECK], &[])?;

   let answer = receive_framed(&socket, MAX_MESSAGE)?
      .and_then(|(bytes, _)| Some(u32::from_be_bytes(bytes.try_into().ok()?)));

   match answer {
      Some(pid) => Ok(pid),
      None => bail!("the shared connection gave no answer"),
   }
}

/// Tells the holder at `path` to exit, at once with `ending` and else once
/// its sessions are over.
pub fn stop(path: &Path, ending: bool) -> Result<()> {
   let socket =
      connect(path).with_context(|| format!("no shared connection at {}", path.display()))?;
   send_framed(&socket, &[if ending { END } else { STOP }], &[])?;
   Ok(())
}
