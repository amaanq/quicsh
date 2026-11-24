//! Carries the datagrams of a connection over the standard input and output
//! of another program, for `QshProxyCommand`. Each datagram travels behind
//! its length in two bytes, the high one first.

use std::{
   env,
   fs::File,
   io::{
      self,
      BufReader,
      ErrorKind,
      Read,
      Write,
   },
   net::{
      Ipv4Addr,
      Ipv6Addr,
      Shutdown,
      SocketAddr,
      UdpSocket,
   },
   os::{
      fd::{
         AsFd as _,
         OwnedFd,
      },
      unix::net::UnixStream,
   },
   process::{
      Child,
      Command,
      Stdio,
   },
   thread,
};

use misstep::{
   Result,
   ResultExt as _,
   bail,
};
use quicsh::pipe::socket_pair;
use rustix::net::{
   AddressFamily,
   SocketType,
};

/// The longest datagram that its two bytes of length can announce.
const LARGEST: usize = 0xFFFF;

/// How much of the other program's output is read at once.
const BUFFER: usize = 256 * 1024;

/// Reads one datagram into `datagram` and returns its length.
fn take(source: &mut impl Read, datagram: &mut [u8]) -> io::Result<usize> {
   let mut prefix = [0; 2];
   source.read_exact(&mut prefix)?;

   let length = usize::from(u16::from_be_bytes(prefix));
   let payload = datagram.get_mut(..length).ok_or(ErrorKind::InvalidData)?;
   source.read_exact(payload)?;

   Ok(length)
}

/// Writes `datagram` behind its length, with `frame` as the scratch space.
fn put(sink: &mut impl Write, frame: &mut Vec<u8>, datagram: &[u8]) -> io::Result<()> {
   let length = u16::try_from(datagram.len()).map_err(|_error| ErrorKind::InvalidInput)?;

   frame.clear();
   frame.extend_from_slice(&length.to_be_bytes());
   frame.extend_from_slice(datagram);

   sink.write_all(frame)
}

/// Copies `source` to `sink` until `source` ends. `io::copy` splices on
/// Linux, which carried a download at 0.1 Gbit/s where this carries 11.
fn pass(source: &mut impl Read, sink: &mut impl Write) -> io::Result<()> {
   let mut buffer = vec![0; BUFFER];

   loop {
      match source.read(&mut buffer) {
         Ok(0) => return Ok(()),
         Ok(length) => sink.write_all(&buffer[..length])?,
         Err(error) if error.kind() == ErrorKind::Interrupted => {},
         Err(error) => return Err(error),
      }
   }
}

/// Starts `command` in the user's shell. Returns it with the stream socket
/// pair that reaches the server through it.
pub fn start(command: &str) -> Result<(Child, OwnedFd)> {
   let shell = env::var_os("SHELL").unwrap_or_else(|| "/bin/sh".into());

   let mut child = Command::new(shell)
      .arg("-c")
      .arg(format!("exec {command}"))
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .spawn()
      .context("starting the QshProxyCommand")?;

   let (Some(mut sink), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
      bail!("the QshProxyCommand started without its pipes");
   };

   // The program frames its datagrams as the link does, so bytes pass
   // through unchanged.
   let (link, near) = socket_pair(AddressFamily::UNIX, SocketType::STREAM)?;
   let mut arriving = UnixStream::from(near);
   let mut leaving = arriving.try_clone()?;
   let mut source = output;

   thread::spawn(move || {
      let _ = pass(&mut source, &mut arriving);

      // The other thread holds this socket too, and the connection has to
      // see that the program is gone.
      let _ = arriving.shutdown(Shutdown::Write);
   });

   thread::spawn(move || {
      let _ = pass(&mut leaving, &mut sink);
   });

   Ok((child, link))
}

/// Carries datagrams between this process's standard input and output and
/// the first of `addresses`, until the input ends. This is the far end of a
/// `QshProxyCommand`, and it logs in nowhere.
pub fn serve(addresses: &[SocketAddr]) -> Result<()> {
   let Some(&address) = addresses.first() else {
      bail!("no address to carry datagrams to");
   };

   let local = if address.is_ipv4() {
      SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
   } else {
      SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
   };

   let socket = UdpSocket::bind(local)?;
   socket.connect(address)?;

   let answers = socket.try_clone()?;
   let mut sink = File::from(io::stdout().as_fd().try_clone_to_owned()?);

   thread::spawn(move || {
      let mut datagram = vec![0; LARGEST];
      let mut frame = Vec::with_capacity(2 + LARGEST);

      loop {
         // A refused datagram shows up here as an error, and the server
         // may yet come back.
         let Ok(length) = answers.recv(&mut datagram) else {
            continue;
         };

         let written = datagram
            .get(..length)
            .is_some_and(|payload| put(&mut sink, &mut frame, payload).is_ok());

         if !written {
            break;
         }
      }
   });

   let input = File::from(io::stdin().as_fd().try_clone_to_owned()?);
   let mut source = BufReader::with_capacity(BUFFER, input);
   let mut datagram = vec![0; LARGEST];

   while let Ok(length) = take(&mut source, &mut datagram) {
      if let Some(payload) = datagram.get(..length) {
         let _ = socket.send(payload);
      }
   }

   Ok(())
}
