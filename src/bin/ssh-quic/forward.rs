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
use ssh_quic::pipe::Waker;

const SOCKS_VERSION: u8 = 5;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_RETRY: Duration = Duration::from_millis(50);

/// A connection a local listener accepted, with the address the server should
/// connect it to.
pub struct Inbound {
   pub socket: OwnedFd,
   pub host:   String,
   pub port:   u16,
}

/// Where a local listener sends its connections.
#[derive(Clone)]
pub enum Target {
   /// `-L`, always the same remote address.
   Fixed { host: String, port: u16 },
   /// `-D`, whatever each connection asks for over SOCKS5.
   Socks,
}

pub struct Local {
   pub bind:   SocketAddr,
   pub target: Target,
}

/// `-R`: the server listens on `port` and connections go to `host:target`
/// as seen from the client.
pub struct Remote {
   pub port:   u16,
   pub host:   String,
   pub target: u16,
}

fn bind(address: Option<&str>, port: &str) -> Result<SocketAddr> {
   let address = match address {
      Some(address) => address.parse::<IpAddr>().context("bad bind address")?,
      None => Ipv4Addr::LOCALHOST.into(),
   };

   Ok(SocketAddr::new(
      address,
      port.parse::<u16>().context("bad port")?,
   ))
}

/// `-L [bind:]port:host:hostport`.
pub struct Fixed(Local);

impl FromStr for Fixed {
   type Err = Report;

   fn from_str(spec: &str) -> Result<Self> {
      let fields: Vec<&str> = spec.split(':').collect();

      let (bind, host, port) = match fields.as_slice() {
         [port, host, target] => (bind(None, port)?, host, target),
         [address, port, host, target] => (bind(Some(address), port)?, host, target),
         _ => bail!("expected [bind:]port:host:hostport, got {spec}"),
      };

      let target = Target::Fixed {
         host: (*host).to_owned(),
         port: port.parse::<u16>().context("bad target port")?,
      };

      Ok(Self(Local { bind, target }))
   }
}

/// `-D [bind:]port`.
pub struct Socks(Local);

impl FromStr for Socks {
   type Err = Report;

   fn from_str(spec: &str) -> Result<Self> {
      let bind = match spec.split_once(':') {
         Some((address, port)) => bind(Some(address), port)?,
         None => bind(None, spec)?,
      };

      Ok(Self(Local {
         bind,
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
   /// accepts on a thread.
   pub fn listen(self, inbound: &Sender<Inbound>, waker: &Arc<Waker>) -> Result<()> {
      let listener =
         TcpListener::bind(self.bind).with_context(|| format!("listening on {}", self.bind))?;
      let inbound = inbound.clone();
      let waker = Arc::clone(waker);

      thread::spawn(move || {
         loop {
            let Ok((stream, _)) = listener.accept() else {
               thread::sleep(ACCEPT_RETRY);
               continue;
            };

            let target = self.target.clone();
            let inbound = inbound.clone();
            let waker = Arc::clone(&waker);

            // A SOCKS client may be slow to state its target, so each
            // connection negotiates on its own thread.
            thread::spawn(move || {
               let Ok((host, port)) = resolve(&stream, target) else {
                  return;
               };

               let socket = OwnedFd::from(stream);

               if inbound.send(Inbound { socket, host, port }).is_ok() {
                  waker.wake();
               }
            });
         }
      });

      Ok(())
   }
}

impl FromStr for Remote {
   type Err = Report;

   /// Parses `-R port:host:hostport`.
   fn from_str(spec: &str) -> Result<Self> {
      let fields: Vec<&str> = spec.split(':').collect();

      let [port, host, target] = fields.as_slice() else {
         bail!("expected port:host:hostport, got {spec}");
      };

      Ok(Self {
         port:   port.parse::<u16>().context("bad port")?,
         host:   (*host).to_owned(),
         target: target.parse::<u16>().context("bad target port")?,
      })
   }
}

fn resolve(stream: &TcpStream, target: Target) -> io::Result<(String, u16)> {
   stream.set_nodelay(true)?;

   match target {
      Target::Fixed { host, port } => Ok((host, port)),
      Target::Socks => {
         stream.set_read_timeout(Some(SOCKS_TIMEOUT))?;
         let address = socks(stream)?;
         stream.set_read_timeout(None)?;
         Ok(address)
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
