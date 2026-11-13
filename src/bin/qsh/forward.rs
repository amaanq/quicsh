//! Local listeners for `-L` and `-D`, and the forward specifications.

use std::{
   io::{
      self,
      Read as _,
      Write as _,
   },
   net::{
      IpAddr,
      Ipv4Addr,
      Ipv6Addr,
      SocketAddr,
      TcpListener,
      TcpStream,
   },
   os::fd::OwnedFd,
   path::PathBuf,
   str::FromStr,
   sync::{
      Arc,
      mpsc::Sender,
   },
   thread,
   time::Duration,
};

use misstep::{
   Report,
   Result,
   ResultExt as _,
   bail,
};
use quicsh::{
   config::expand,
   forward::Bound,
   pipe::Waker,
};

/// SOCKS protocol version this proxy speaks.
const SOCKS_VERSION: u8 = 5;
/// SOCKS command that opens a TCP connection.
const SOCKS_CONNECT: u8 = 1;
/// How long a SOCKS client may take to name its target.
const SOCKS_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause after a failed accept.
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// Where a forwarded connection ends up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
   /// A TCP port, connected to from the other side.
   Tcp {
      /// Host to connect to.
      host: String,
      /// Port to connect to.
      port: u16,
   },
   /// A Unix socket on the other side.
   Unix(String),
}

/// A connection a local listener accepted, with where the server should
/// connect it to.
pub struct Inbound {
   /// The accepted connection.
   pub socket:      OwnedFd,
   /// What the server connects to.
   pub destination: Destination,
}

/// Where a local listener sends its connections.
#[derive(Clone)]
pub enum Target {
   /// `-L`, always the same place.
   Fixed(Destination),
   /// `-D`, whatever each connection asks for over SOCKS5.
   Socks,
}

/// Where a local listener sits.
#[derive(Debug, PartialEq, Eq)]
pub enum Place {
   /// A TCP address.
   Tcp(SocketAddr),
   /// A Unix socket.
   Unix(PathBuf),
}

/// A local listener and where its connections go.
pub struct Local {
   /// Where the listener sits.
   pub bind:   Place,
   /// Where accepted connections are sent.
   pub target: Target,
}

/// Where the server listens for `-R`.
#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
   /// A loopback port, 0 to let the server choose.
   Port(u16),
   /// A Unix socket, from the account's home when relative.
   Path(String),
}

/// `-R`: the server listens and connections go to `target` as seen from
/// the client.
pub struct Remote {
   /// Where the server listens.
   pub listen: Entry,
   /// What the client connects to.
   pub target: Destination,
}

/// Parses a bind address and port, with loopback as the default address.
fn bind(address: Option<&str>, port: &str) -> Result<SocketAddr> {
   let ip = match address {
      Some(text) => text.parse::<IpAddr>().context("bad bind address")?,
      None => Ipv4Addr::LOCALHOST.into(),
   };

   Ok(SocketAddr::new(
      ip,
      port.parse::<u16>().context("bad port")?,
   ))
}

/// Splits a forward into the fields that say where to listen and the
/// destination. As in OpenSSH, a field with a slash is a Unix socket.
fn split(spec: &str) -> Result<(Vec<&str>, Destination)> {
   let mut fields = spec.split(':').collect::<Vec<&str>>();

   let destination = match *fields.as_slice() {
      [.., path] if path.contains('/') => {
         fields.truncate(fields.len() - 1);
         Destination::Unix(path.to_owned())
      },
      [.., host, port] => {
         let parsed = port.parse::<u16>().context("bad target port")?;
         let named = host.to_owned();

         fields.truncate(fields.len() - 2);
         Destination::Tcp {
            host: named,
            port: parsed,
         }
      },
      _ => bail!("no destination in {spec}"),
   };

   Ok((fields, destination))
}

/// `-L [bind:]port:host:hostport`, where a path may stand for either half.
pub struct Fixed(Local);

impl FromStr for Fixed {
   type Err = Report;

   fn from_str(spec: &str) -> Result<Self> {
      let (fields, destination) = split(spec)?;

      let place = match *fields.as_slice() {
         [path] if path.contains('/') => Place::Unix(expand(path)),
         [port] => Place::Tcp(bind(None, port)?),
         [address, port] => Place::Tcp(bind(Some(address), port)?),
         _ => bail!("expected [bind:]port:host:hostport, got {spec}"),
      };

      Ok(Self(Local {
         bind:   place,
         target: Target::Fixed(destination),
      }))
   }
}

/// `-D [bind:]port`.
pub struct Socks(Local);

impl FromStr for Socks {
   type Err = Report;

   fn from_str(spec: &str) -> Result<Self> {
      let place = match spec.split_once(':') {
         Some((address, port)) => bind(Some(address), port)?,
         None => bind(None, spec)?,
      };

      Ok(Self(Local {
         bind:   Place::Tcp(place),
         target: Target::Socks,
      }))
   }
}

impl From<Fixed> for Local {
   fn from(fixed: Fixed) -> Self {
      fixed.0
   }
}

impl From<Socks> for Local {
   fn from(socks: Socks) -> Self {
      socks.0
   }
}

impl Local {
   /// Binds now, so a taken port fails before the connection starts, then
   /// accepts on a thread. A Unix socket's file lasts as long as what this
   /// returns.
   pub fn listen(self, inbound: &Sender<Inbound>, waker: &Arc<Waker>) -> Result<Option<Bound>> {
      let sender = inbound.clone();
      let notifier = Arc::clone(waker);

      let address = match self.bind {
         Place::Tcp(address) => address,
         Place::Unix(path) => {
            let Target::Fixed(destination) = self.target else {
               bail!("a SOCKS proxy listens on a port");
            };

            let (bound, listener) =
               Bound::listen(&path).with_context(|| format!("listening on {}", path.display()))?;

            thread::spawn(move || -> ! {
               loop {
                  let Ok((stream, _)) = listener.accept() else {
                     thread::sleep(ACCEPT_RETRY);
                     continue;
                  };

                  let accepted = Inbound {
                     socket:      stream.into(),
                     destination: destination.clone(),
                  };

                  if sender.send(accepted).is_ok() {
                     notifier.wake();
                  }
               }
            });

            return Ok(Some(bound));
         },
      };

      let listener =
         TcpListener::bind(address).with_context(|| format!("listening on {address}"))?;

      thread::spawn(move || -> ! {
         loop {
            let Ok((stream, _)) = listener.accept() else {
               thread::sleep(ACCEPT_RETRY);
               continue;
            };

            let target = self.target.clone();
            let forward = sender.clone();
            let notify = Arc::clone(&notifier);

            // A SOCKS client may be slow to state its target, so each
            // connection negotiates on its own thread.
            thread::spawn(move || {
               let Ok(destination) = resolve(&stream, target) else {
                  return;
               };

               let accepted = Inbound {
                  socket: stream.into(),
                  destination,
               };

               if forward.send(accepted).is_ok() {
                  notify.wake();
               }
            });
         }
      });

      Ok(None)
   }
}

impl FromStr for Remote {
   type Err = Report;

   /// Parses `-R port:host:hostport`, where a path may stand for either
   /// half.
   fn from_str(spec: &str) -> Result<Self> {
      let (fields, target) = split(spec)?;

      let listen = match *fields.as_slice() {
         [path] if path.contains('/') => Entry::Path(path.to_owned()),
         [port] => Entry::Port(port.parse::<u16>().context("bad port")?),
         _ => bail!("expected port:host:hostport, got {spec}"),
      };

      Ok(Self { listen, target })
   }
}

/// Finds the address a new connection should reach.
fn resolve(stream: &TcpStream, target: Target) -> io::Result<Destination> {
   stream.set_nodelay(true)?;

   match target {
      Target::Fixed(destination) => Ok(destination),
      Target::Socks => {
         stream.set_read_timeout(Some(SOCKS_TIMEOUT))?;
         let (host, port) = socks(stream)?;
         stream.set_read_timeout(None)?;
         Ok(Destination::Tcp { host, port })
      },
   }
}

/// Runs the SOCKS5 handshake (RFC 1928) and returns the requested address.
///
/// Success is reported before the server has connected, so the client's first
/// bytes travel with the request. A connection the server cannot make then
/// shows up as a closed socket instead of a SOCKS error.
fn socks(mut stream: &TcpStream) -> io::Result<(String, u16)> {
   let invalid = || io::Error::from(io::ErrorKind::InvalidData);

   let mut greeting = [0; 2];
   stream.read_exact(&mut greeting)?;

   if greeting[0] != SOCKS_VERSION {
      return Err(invalid());
   }

   let mut methods = vec![0; usize::from(greeting[1])];
   stream.read_exact(&mut methods)?;
   stream.write_all(&[SOCKS_VERSION, 0])?;

   let mut request = [0; 4];
   stream.read_exact(&mut request)?;

   if request[0] != SOCKS_VERSION || request[1] != SOCKS_CONNECT {
      stream.write_all(&[SOCKS_VERSION, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
      return Err(invalid());
   }

   let host = match request[3] {
      1 => {
         let mut address = [0; 4];
         stream.read_exact(&mut address)?;
         Ipv4Addr::from(address).to_string()
      },
      3 => {
         let mut length = [0; 1];
         stream.read_exact(&mut length)?;

         let mut name = vec![0; usize::from(length[0])];
         stream.read_exact(&mut name)?;
         String::from_utf8(name).map_err(|_| invalid())?
      },
      4 => {
         let mut address = [0; 16];
         stream.read_exact(&mut address)?;
         Ipv6Addr::from(address).to_string()
      },
      _ => return Err(invalid()),
   };

   let mut port = [0; 2];
   stream.read_exact(&mut port)?;
   stream.write_all(&[SOCKS_VERSION, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;

   Ok((host, u16::from_be_bytes(port)))
}

#[cfg(test)]
mod tests {
   use std::path::PathBuf;

   use crate::forward::{
      Destination,
      Entry,
      Fixed,
      Place,
      Remote,
      Target,
   };

   /// The destination of a `-L` spec.
   fn destination(spec: &str) -> Destination {
      let Fixed(local) = spec.parse::<Fixed>().unwrap();

      match local.target {
         Target::Fixed(destination) => destination,
         Target::Socks => panic!("{spec} is no SOCKS proxy"),
      }
   }

   /// `-L` binds loopback unless the spec names an address.
   #[test]
   fn local_spec() {
      let Fixed(short) = "8080:example.com:80".parse::<Fixed>().unwrap();
      let Fixed(long) = "0.0.0.0:8080:example.com:80".parse::<Fixed>().unwrap();

      assert_eq!(
         short.bind,
         Place::Tcp("127.0.0.1:8080".parse().unwrap()),
         "default address"
      );
      assert_eq!(
         long.bind,
         Place::Tcp("0.0.0.0:8080".parse().unwrap()),
         "named address"
      );
      assert_eq!(
         destination("8080:example.com:80"),
         Destination::Tcp {
            host: "example.com".to_owned(),
            port: 80,
         },
         "target"
      );
   }

   /// A field with a slash is a Unix socket, on either side.
   #[test]
   fn socket_specs() {
      let Fixed(both) = "/tmp/near.sock:/run/far.sock".parse::<Fixed>().unwrap();
      let Fixed(mixed) = "/tmp/near.sock:example.com:80".parse::<Fixed>().unwrap();
      let remote = "/run/far.sock:localhost:22".parse::<Remote>().unwrap();
      let ported = "0:/tmp/near.sock".parse::<Remote>().unwrap();

      assert_eq!(
         both.bind,
         Place::Unix(PathBuf::from("/tmp/near.sock")),
         "local socket"
      );
      assert_eq!(
         destination("9000:/run/far.sock"),
         Destination::Unix("/run/far.sock".to_owned()),
         "port to socket"
      );
      assert_eq!(
         mixed.bind,
         Place::Unix(PathBuf::from("/tmp/near.sock")),
         "socket to port"
      );
      assert_eq!(
         remote.listen,
         Entry::Path("/run/far.sock".to_owned()),
         "remote socket"
      );
      assert_eq!(ported.listen, Entry::Port(0), "remote port");
      assert_eq!(
         ported.target,
         Destination::Unix("/tmp/near.sock".to_owned()),
         "socket on this side"
      );
   }

   /// Specs with missing fields or bad ports fail.
   #[test]
   fn malformed_specs() {
      assert!("8080".parse::<Fixed>().is_err(), "no target");
      assert!(
         "8080:example.com:http".parse::<Fixed>().is_err(),
         "named port"
      );
      assert!(
         "70000:example.com:80".parse::<Remote>().is_err(),
         "port out of range"
      );
      assert!(
         "1.2.3.4:/tmp/near.sock:/run/far.sock"
            .parse::<Fixed>()
            .is_err(),
         "address before a socket"
      );
   }
}
