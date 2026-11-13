//! The part of OpenSSH's `ssh_config` that names a server and a login.
//!
//! - `Host` blocks with `*`, `?` and `!` patterns, `Match all`, and `Include`.
//!   Any other `Match` block is skipped, since its conditions are not
//!   evaluated.
//! - `HostName`, `User`, `IdentityFile`, `IdentityAgent`, `ProxyJump`,
//!   `ForwardAgent`, the three forward keywords, `ClearAllForwardings`,
//!   `RequestTTY`, `RemoteCommand`, `StrictHostKeyChecking` and `HostKeyAlias`.
//!   `Port` is ignored, because it names sshd's TCP port and says nothing about
//!   the UDP port.
//! - `QshPort` for the UDP port, which OpenSSH skips once the file says
//!   `IgnoreUnknown QshPort`.
//! - As in OpenSSH, the first value found for a keyword wins and identity files
//!   add up.

use std::{
   env,
   fs,
   path::{
      Path,
      PathBuf,
   },
};

use crate::known_hosts::glob;

/// How deep `Include` may nest, which is OpenSSH's limit.
const MAX_DEPTH: usize = 16;

/// What the configuration says about one host.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Host {
   /// The name to connect to in place of the one given.
   pub hostname:       Option<String>,
   /// The account to log in to.
   pub user:           Option<String>,
   /// The UDP port as written, which the caller parses.
   pub port:           Option<String>,
   /// Private key files to log in with, in order.
   pub identity_files: Vec<PathBuf>,
   /// The hosts to connect through, as written.
   pub jump:           Option<String>,
   /// `IdentityAgent`, as written.
   pub agent:          Option<String>,
   /// `ForwardAgent`, as written.
   pub forward_agent:  Option<String>,
   /// Every `LocalForward`, as written.
   pub locals:         Vec<String>,
   /// Every `RemoteForward`, as written.
   pub remotes:        Vec<String>,
   /// Every `DynamicForward`, as written.
   pub dynamics:       Vec<String>,
   /// `ClearAllForwardings`, as written.
   pub clear:          Option<String>,
   /// `RequestTTY`, as written.
   pub terminal:       Option<String>,
   /// `RemoteCommand`, as written.
   pub command:        Option<String>,
   /// `StrictHostKeyChecking`, as written.
   pub strict:         Option<String>,
   /// The name to look the host key up under.
   pub alias:          Option<String>,
}

/// Replaces a leading `~/` with the home directory.
#[must_use]
pub fn expand(path: &str) -> PathBuf {
   match (path.strip_prefix("~/"), env::var_os("HOME")) {
      (Some(rest), Some(home)) => Path::new(&home).join(rest),
      _ => PathBuf::from(path),
   }
}

/// Whether a `Host` line's patterns cover `name`.
fn covers<'pattern>(patterns: impl Iterator<Item = &'pattern str>, name: &str) -> bool {
   let mut matched = false;

   for pattern in patterns {
      match pattern.strip_prefix('!') {
         Some(negated) if glob(negated.as_bytes(), name.as_bytes()) => return false,
         Some(_) => {},
         None => matched |= glob(pattern.as_bytes(), name.as_bytes()),
      }
   }

   matched
}

impl Host {
   /// Adds what the file at `path` says about `name`. A file that cannot be
   /// read adds nothing.
   pub fn read(&mut self, path: &Path, name: &str) {
      self.include(path, name, true, 0);
   }

   /// Adds what command line options say, each in the form of one line of
   /// the file. They cannot include other files.
   pub fn options(&mut self, lines: &[String], name: &str) {
      self.apply(&lines.join("\n"), Path::new(""), name, true, MAX_DEPTH);
   }

   /// Reads one file, which applies from its first line when `active`.
   fn include(&mut self, path: &Path, name: &str, active: bool, depth: usize) {
      if let Ok(text) = fs::read_to_string(path) {
         self.apply(&text, path.parent().unwrap_or(path), name, active, depth);
      }
   }

   /// Adds what `text` says about `name`. Relative `Include` paths start at
   /// `base`.
   fn apply(&mut self, text: &str, base: &Path, name: &str, mut active: bool, depth: usize) {
      for line in text.lines().map(str::trim) {
         if line.is_empty() || line.starts_with('#') {
            continue;
         }

         let (keyword, rest) = line
            .split_once(|symbol: char| symbol.is_whitespace() || symbol == '=')
            .unwrap_or((line, ""));
         let value = rest
            .trim_start_matches(|symbol: char| symbol.is_whitespace() || symbol == '=')
            .trim_matches('"');

         let lowered = keyword.to_ascii_lowercase();

         let single = match lowered.as_str() {
            "user" => Some(&mut self.user),
            "qshport" => Some(&mut self.port),
            "proxyjump" => Some(&mut self.jump),
            "identityagent" => Some(&mut self.agent),
            "forwardagent" => Some(&mut self.forward_agent),
            "clearallforwardings" => Some(&mut self.clear),
            "requesttty" => Some(&mut self.terminal),
            "remotecommand" => Some(&mut self.command),
            "stricthostkeychecking" => Some(&mut self.strict),
            "hostkeyalias" => Some(&mut self.alias),
            _ => None,
         };

         if let Some(slot) = single {
            if active && !value.is_empty() && slot.is_none() {
               *slot = Some(value.to_owned());
            }

            continue;
         }

         match lowered.as_str() {
            "host" => active = covers(value.split_whitespace(), name),
            "match" => active = value.eq_ignore_ascii_case("all"),
            _ if !active || value.is_empty() => {},
            "hostname" if self.hostname.is_none() => {
               self.hostname = Some(value.replace("%h", name));
            },
            "identityfile" => self.identity_files.push(expand(value)),
            "localforward" => self.locals.push(value.to_owned()),
            "remoteforward" => self.remotes.push(value.to_owned()),
            "dynamicforward" => self.dynamics.push(value.to_owned()),
            "include" if depth < MAX_DEPTH => {
               for pattern in value.split_whitespace() {
                  for path in matching(&base.join(expand(pattern))) {
                     self.include(&path, name, active, depth + 1);
                  }
               }
            },
            _ => {},
         }
      }
   }
}

/// The files an `Include` path names, where the last component may hold `*`
/// and `?`.
fn matching(path: &Path) -> Vec<PathBuf> {
   let Some(pattern) = path.file_name().and_then(|file| file.to_str()) else {
      return Vec::new();
   };

   if !pattern.contains(['*', '?']) {
      return vec![path.to_owned()];
   }

   let Some(Ok(entries)) = path.parent().map(fs::read_dir) else {
      return Vec::new();
   };

   let mut found = entries
      .filter_map(Result::ok)
      .filter(|entry| glob(pattern.as_bytes(), entry.file_name().as_encoded_bytes()))
      .map(|entry| entry.path())
      .collect::<Vec<PathBuf>>();

   found.sort();
   found
}

#[cfg(test)]
mod tests {
   use std::path::{
      Path,
      PathBuf,
   };

   use crate::config::Host;

   /// What `text` says about `name`.
   fn lookup(text: &str, name: &str) -> Host {
      let mut host = Host::default();
      host.apply(text, Path::new("/nonexistent"), name, true, 0);
      host
   }

   const CONFIG: &str = "
      # comment
      User fallback
      Host box *.lan !bad.lan
         HostName=%h.example.com
         User \"alice\"
         IdentityFile /keys/first
      Match user build
         User builder
      Host *
         User everyone
         IdentityFile /keys/second
         Port 2222
         QshPort 4222
   ";

   /// The first value wins, identity files add up and unknown keywords pass.
   #[test]
   fn first_value_wins() {
      let host = lookup(CONFIG, "box");

      assert_eq!(
         host.hostname.as_deref(),
         Some("box.example.com"),
         "name with %h"
      );
      assert_eq!(
         host.user.as_deref(),
         Some("fallback"),
         "set before any Host line"
      );
      assert_eq!(
         host.identity_files,
         [PathBuf::from("/keys/first"), PathBuf::from("/keys/second")],
         "both blocks"
      );
   }

   /// A negated pattern keeps a host out of a block, and a `Match` block
   /// with conditions applies to nobody.
   #[test]
   fn negation_and_match() {
      let host = lookup(&CONFIG.replacen("User fallback", "", 1), "bad.lan");

      assert_eq!(host.hostname, None, "negated in the first block");
      assert_eq!(host.port.as_deref(), Some("4222"), "not the TCP port");
      assert_eq!(
         host.user.as_deref(),
         Some("everyone"),
         "not the Match block"
      );
      assert_eq!(
         host.identity_files,
         [PathBuf::from("/keys/second")],
         "wildcard block only"
      );
   }
}
