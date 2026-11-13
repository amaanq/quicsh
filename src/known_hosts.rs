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
   let lowered = host.to_ascii_lowercase();

   match lookup(text, &name(&lowered, port), key) {
      Trust::Unknown => {
         match lookup(text, &lowered, key) {
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

/// The `[host]:port` form that names one port of a host.
fn name(host: &str, port: u16) -> String {
   format!("[{host}]:{port}")
}

/// What the entries for `name` say about `key`.
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

      let Ok(parsed) = listed.parse::<PublicKey>() else {
         continue;
      };

      match (marker, parsed == *key) {
         ("@revoked", true) => return Trust::Revoked,
         ("@revoked", false) => {},
         (_, true) => trust = Trust::Known,
         (_, false) if trust == Trust::Unknown => trust = Trust::Changed,
         (_, false) => {},
      }
   }

   trust
}

/// Whether a host field, hashed or a pattern list, covers `name`.
fn matches(hosts: &str, name: &str) -> bool {
   if let Some(hashed) = hosts.strip_prefix("|1|") {
      let Some((salt, hash)) = hashed.split_once('|') else {
         return false;
      };

      let (Ok(seed), Ok(expected)) = (decode(salt), decode(hash)) else {
         return false;
      };

      let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &seed);
      return verify(&key, name.as_bytes(), &expected).is_ok();
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

/// Whether `name` matches a pattern with `*` and `?`.
#[must_use]
pub fn glob(pattern: &[u8], name: &[u8]) -> bool {
   match pattern.split_first() {
      None => name.is_empty(),
      Some((&b'*', rest)) => (0..=name.len()).any(|skip| glob(rest, &name[skip..])),
      Some((&b'?', rest)) => !name.is_empty() && glob(rest, &name[1..]),
      Some((literal, rest)) => name.first() == Some(literal) && glob(rest, &name[1..]),
   }
}

#[cfg(test)]
mod tests {
   use ring::hmac::{
      HMAC_SHA1_FOR_LEGACY_USE_ONLY,
      Key,
      sign,
   };

   use crate::{
      key::{
         PublicKey,
         encode,
      },
      known_hosts::{
         Trust,
         check,
         entry,
      },
   };

   /// The key the server presents.
   const OURS: PublicKey = PublicKey::Ed25519([1; 32]);
   /// Some other key.
   const THEIRS: PublicKey = PublicKey::Ed25519([2; 32]);

   /// A `[host]:port` entry outranks the plain entry for the same host.
   #[test]
   fn port_entry_decides_alone() {
      let text = format!("{}host {OURS}\n", entry("Host", 4222, &THEIRS));

      assert_eq!(
         check(&text, "host", 4222, &THEIRS),
         Trust::Known,
         "listed for the port"
      );
      assert_eq!(
         check(&text, "HOST", 4222, &OURS),
         Trust::Changed,
         "port entry differs"
      );
   }

   /// The sshd entry can confirm a key but cannot contradict one.
   #[test]
   fn plain_entry_only_confirms() {
      let text = format!("# comment\nhost,10.0.0.1 {OURS} comment\n");

      assert_eq!(
         check(&text, "host", 22, &OURS),
         Trust::Known,
         "sshd key reused"
      );
      assert_eq!(
         check(&text, "10.0.0.1", 22, &THEIRS),
         Trust::Unknown,
         "other port, other key"
      );
   }

   /// A revoked key is refused even when another line lists it.
   #[test]
   fn revoked_wins() {
      let text = format!("host {OURS}\n@revoked * {OURS}\n@revoked * {THEIRS}\n");

      assert_eq!(
         check(&text, "host", 22, &OURS),
         Trust::Revoked,
         "revoked for every host"
      );
   }

   /// A negated pattern excludes a host that a wildcard would cover.
   #[test]
   fn negation_excludes() {
      let text = format!("*.example.com,!bad.example.com {OURS}\n");

      assert_eq!(
         check(&text, "good.example.com", 22, &OURS),
         Trust::Known,
         "wildcard"
      );
      assert_eq!(
         check(&text, "bad.example.com", 22, &OURS),
         Trust::Unknown,
         "negated"
      );
   }

   /// A hashed host field matches the name it was made from.
   #[test]
   fn hashed_host_matches() {
      let salt = [9; 20];
      let hash = sign(
         &Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt),
         b"[host]:4222",
      );
      let text = format!("|1|{}|{} {OURS}\n", encode(&salt), encode(hash.as_ref()));

      assert_eq!(
         check(&text, "host", 4222, &OURS),
         Trust::Known,
         "hash of the name"
      );
      assert_eq!(
         check(&text, "other", 4222, &OURS),
         Trust::Unknown,
         "hash of another name"
      );
   }
}
