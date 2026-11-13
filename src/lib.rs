pub mod agent;
pub mod auth;
pub mod error;
pub mod key;
pub mod known_hosts;
pub mod tls;
pub mod transport;
pub mod wire;

/// UDP port 22 is free on hosts that run sshd, which listens on TCP only.
pub const DEFAULT_PORT: u16 = 22;
