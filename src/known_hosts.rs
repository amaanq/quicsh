//! Host key lookup in OpenSSH `known_hosts` text.

use ring::hmac::{
   HMAC_SHA1_FOR_LEGACY_USE_ONLY,
   Key,
   verify,
};

use crate::key::{
   PublicKey,
   decode,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
   /// The host is listed with this key.
   Known,
   /// The host has no ed25519 entry.
   Unknown,
   /// The host is listed with a different ed25519 key.
   Changed,
   /// The key is listed as revoked for this host.
   Revoked,
}

/// Decides whether `key` is trusted for `host` on `port`.
///
/// Entries for `[host]:port` decide alone when present. Otherwise the plain
/// `host` entry that sshd on TCP port 22 produced can confirm the key, since a
/// server may reuse its sshd host key. A different key there proves nothing
/// about this port, so it reports [`Trust::Unknown`].
#[must_use]
pub fn check(text: &str, host: &str, port: u16, key: &PublicKey) -> Trust {
   let host = host.to_ascii_lowercase();

   match lookup(text, &name(&host, port), key) {
      Trust::Unknown => {
         match lookup(text, &host, key) {
            Trust::Changed => Trust::Unknown,
            other => other,
         }
      },
      other => other,
   }
}

/// The line that records `key` for `host` on `port`.
#[must_use]
pub fn entry(host: &str, port: u16, key: &PublicKey) -> String {
   format!("{} {key}\n", name(&host.to_ascii_lowercase(), port))
}

fn name(host: &str, port: u16) -> String {
   format!("[{host}]:{port}")
}

fn lookup(text: &str, name: &str, key: &PublicKey) -> Trust {
   let mut trust = Trust::Unknown;

   for line in text.lines().map(str::trim) {
      if line.is_empty() || line.starts_with('#') {
         continue;
      }

      let (marker, rest) = if line.starts_with('@') {
         line.split_once(char::is_whitespace).unwrap_or((line, ""))
      } else {
         ("", line)
      };

      let Some((hosts, listed)) = rest.trim_start().split_once(char::is_whitespace) else {
         continue;
      };

      if marker == "@cert-authority" || !matches(hosts, name) {
         continue;
      }

      let Ok(listed) = listed.parse::<PublicKey>() else {
         continue;
      };

      match (marker, listed == *key) {
         ("@revoked", true) => return Trust::Revoked,
         ("@revoked", false) => {},
         (_, true) => trust = Trust::Known,
         (_, false) if trust == Trust::Unknown => trust = Trust::Changed,
         (_, false) => {},
      }
   }

   trust
}

fn matches(hosts: &str, name: &str) -> bool {
   if let Some(hashed) = hosts.strip_prefix("|1|") {
      let Some((salt, hash)) = hashed.split_once('|') else {
         return false;
      };

      let (Ok(salt), Ok(hash)) = (decode(salt), decode(hash)) else {
         return false;
      };

      let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
      return verify(&key, name.as_bytes(), &hash).is_ok();
   }

   let mut matched = false;

   for pattern in hosts.split(',') {
      match pattern.strip_prefix('!') {
         Some(negated) if glob(negated.as_bytes(), name.as_bytes()) => return false,
         Some(_) => {},
         None => matched |= glob(pattern.as_bytes(), name.as_bytes()),
      }
   }

   matched
}

fn glob(pattern: &[u8], name: &[u8]) -> bool {
   match pattern.split_first() {
      None => name.is_empty(),
      Some((b'*', rest)) => (0..=name.len()).any(|skip| glob(rest, &name[skip..])),
      Some((b'?', rest)) => !name.is_empty() && glob(rest, &name[1..]),
      Some((literal, rest)) => name.first() == Some(literal) && glob(rest, &name[1..]),
   }
}
