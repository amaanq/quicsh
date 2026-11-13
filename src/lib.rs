pub mod agent;
pub mod auth;
pub mod control;
pub mod error;
pub mod forward;
pub mod key;
pub mod known_hosts;
pub mod pipe;
pub mod relay;
pub mod tls;
pub mod transport;
pub mod wire;

/// UDP port 22 is free on hosts that run sshd.
pub const DEFAULT_PORT: u16 = 22;
