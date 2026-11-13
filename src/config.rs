//! The part of OpenSSH's `ssh_config` that names a server and a login.
//!
//! - `Host` blocks with `*`, `?` and `!` patterns, and `Include`.
//! - `Match` blocks with `all`, `host`, `originalhost`, `user` and `localuser`.
//!   A block with any other condition is skipped, since nothing here runs a
//!   command or reads the file twice.
//! - `HostName`, `User`, `IdentityFile`, `CertificateFile`, `IdentityAgent`,
//!   `ProxyJump`, `ForwardAgent`, the three forward keywords,
//!   `ClearAllForwardings`, `RequestTTY`, `RemoteCommand`,
//!   `StrictHostKeyChecking`, `HostKeyAlias`, `UserKnownHostsFile`,
//!   `GlobalKnownHostsFile`, `ControlMaster`, `ControlPath`, `ControlPersist`,
//!   `ConnectTimeout`, `EscapeChar`, `SendEnv` and `SetEnv`. As in OpenSSH,
//!   only the first `SetEnv` line counts. `Port` is ignored, because it names
//!   sshd's TCP port and says nothing about the UDP port.
//! - `QshPort` for the UDP port, which OpenSSH skips once the file says
//!   `IgnoreUnknown QshPort`.
//! - As in OpenSSH, the first value found for a keyword wins and identity files
//!   add up.

use std::{
   env,
   fs,
   mem,
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
   pub hostname:        Option<String>,
   /// The account to log in to.
   pub user:            Option<String>,
   /// The UDP port as written, which the caller parses.
   pub port:            Option<String>,
   /// Private key files to log in with, in order.
   pub identity_files:  Vec<PathBuf>,
   /// The hosts to connect through, as written.
   pub jump:            Option<String>,
   /// `IdentityAgent`, as written.
   pub agent:           Option<String>,
   /// `ForwardAgent`, as written.
   pub forward_agent:   Option<String>,
   /// Every `LocalForward`, as written.
   pub locals:          Vec<String>,
   /// Every `RemoteForward`, as written.
   pub remotes:         Vec<String>,
   /// Every `DynamicForward`, as written.
   pub dynamics:        Vec<String>,
   /// `ClearAllForwardings`, as written.
   pub clear:           Option<String>,
   /// `RequestTTY`, as written.
   pub terminal:        Option<String>,
   /// `RemoteCommand`, as written.
   pub command:         Option<String>,
   /// `StrictHostKeyChecking`, as written.
   pub strict:          Option<String>,
   /// The name to look the host key up under.
   pub alias:           Option<String>,
   /// `ControlMaster`, as written.
   pub control_master:  Option<String>,
   /// `ControlPath`, as written.
   pub control_path:    Option<String>,
   /// `ControlPersist`, as written.
   pub control_persist: Option<String>,
   /// Every `CertificateFile`, in order.
   pub certificates:    Vec<PathBuf>,
   /// `ConnectTimeout`, as written.
   pub connect_timeout: Option<String>,
   /// `UserKnownHostsFile`, as written.
   pub known_user:      Option<String>,
   /// `GlobalKnownHostsFile`, as written.
   pub known_global:    Option<String>,
   /// `EscapeChar`, as written.
   pub escape:          Option<String>,
   /// The `SendEnv` patterns that name local variables to pass on.
   pub send_env:        Vec<String>,
   /// The `NAME=VALUE` words of the first `SetEnv` line.
   pub set_env:         Vec<String>,
}

/// Replaces a leading `~/` with the home directory.
#[must_use]
pub fn expand(path: &str) -> PathBuf {
   match (path.strip_prefix("~/"), env::var_os("HOME")) {
      (Some(rest), Some(home)) => Path::new(&home).join(rest),
      _ => PathBuf::from(path),
   }
}

/// Who a configuration is read for.
#[derive(Clone, Copy)]
pub struct Target<'name> {
   /// The host as the command line names it.
   pub host:  &'name str,
   /// The account the command line names, when it names one.
   pub user:  Option<&'name str>,
   /// The local account.
   pub local: &'name str,
}

/// Splits a line's arguments at blanks, where double quotes keep blanks in
/// a word and are dropped.
fn words(text: &str) -> Vec<String> {
   let mut found = Vec::new();
   let mut word = String::new();
   let mut quoted = false;

   for symbol in text.chars() {
      match symbol {
         '"' => quoted = !quoted,
         blank if blank.is_whitespace() && !quoted => {
            if !word.is_empty() {
               found.push(mem::take(&mut word));
            }
         },
         other => word.push(other),
      }
   }

   if !word.is_empty() {
      found.push(word);
   }

   found
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
   /// Adds what the file at `path` says about `target`. A file that cannot
   /// be read adds nothing.
   pub fn read(&mut self, path: &Path, target: Target<'_>) {
      self.include(path, target, true, 0);
   }

   /// Adds what command line options say, each in the form of one line of
   /// the file. They cannot include other files.
   pub fn options(&mut self, lines: &[String], target: Target<'_>) {
      self.apply(&lines.join("\n"), Path::new(""), target, true, MAX_DEPTH);
   }

   /// Reads one file, which applies from its first line when `active`.
   fn include(&mut self, path: &Path, target: Target<'_>, active: bool, depth: usize) {
      if let Ok(text) = fs::read_to_string(path) {
         self.apply(&text, path.parent().unwrap_or(path), target, active, depth);
      }
   }

   /// Whether every condition of a `Match` line holds, given what was read
   /// so far. A condition this parser cannot check, such as `exec`, holds
   /// for nobody, and so does one that needs a second pass over the file.
   fn matched(&self, conditions: &str, target: Target<'_>) -> bool {
      let mut words = conditions.split_whitespace().peekable();

      if words.peek().is_none() {
         return false;
      }

      while let Some(word) = words.next() {
         let (negated, keyword) = word
            .strip_prefix('!')
            .map_or((false, word), |rest| (true, rest));

         let holds = match keyword.to_ascii_lowercase().as_str() {
            "all" => true,
            checked => {
               let subject = match checked {
                  "host" => self.hostname.as_deref().unwrap_or(target.host),
                  "originalhost" => target.host,
                  "user" => target.user.or(self.user.as_deref()).unwrap_or(target.local),
                  "localuser" => target.local,
                  _ => return false,
               };

               let Some(patterns) = words.next() else {
                  return false;
               };

               covers(patterns.trim_matches('"').split(','), subject)
            },
         };

         if holds == negated {
            return false;
         }
      }

      true
   }

   /// Adds what `text` says about `target`. Relative `Include` paths start
   /// at `base`.
   fn apply(
      &mut self,
      text: &str,
      base: &Path,
      target: Target<'_>,
      mut active: bool,
      depth: usize,
   ) {
      let name = target.host;

      for line in text.lines().map(str::trim) {
         if line.is_empty() || line.starts_with('#') {
            continue;
         }

         let (keyword, rest) = line
            .split_once(|symbol: char| symbol.is_whitespace() || symbol == '=')
            .unwrap_or((line, ""));
         let arguments =
            rest.trim_start_matches(|symbol: char| symbol.is_whitespace() || symbol == '=');
         let value = arguments.trim_matches('"');

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
            "controlmaster" => Some(&mut self.control_master),
            "controlpath" => Some(&mut self.control_path),
            "controlpersist" => Some(&mut self.control_persist),
            "connecttimeout" => Some(&mut self.connect_timeout),
            "escapechar" => Some(&mut self.escape),
            "userknownhostsfile" => Some(&mut self.known_user),
            "globalknownhostsfile" => Some(&mut self.known_global),
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
            "match" => active = self.matched(value, target),
            _ if !active || value.is_empty() => {},
            "hostname" if self.hostname.is_none() => {
               self.hostname = Some(value.replace("%h", name));
            },
            "identityfile" => self.identity_files.push(expand(value)),
            "certificatefile" => self.certificates.push(expand(value)),
            "localforward" => self.locals.push(value.to_owned()),
            "remoteforward" => self.remotes.push(value.to_owned()),
            "dynamicforward" => self.dynamics.push(value.to_owned()),
            "sendenv" => {
               for word in words(arguments) {
                  match word.strip_prefix('-') {
                     Some(dropped) => {
                        self
                           .send_env
                           .retain(|kept| !glob(dropped.as_bytes(), kept.as_bytes()));
                     },
                     None => self.send_env.push(word),
                  }
               }
            },
            "setenv" if self.set_env.is_empty() => self.set_env = words(arguments),
            "include" if depth < MAX_DEPTH => {
               for pattern in value.split_whitespace() {
                  for path in matching(&base.join(expand(pattern))) {
                     self.include(&path, target, active, depth + 1);
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

   use crate::config::{
      Host,
      Target,
   };

   /// What `text` says about `name` for the local account `me`, who names
   /// the remote account `user`.
   fn lookup_as(text: &str, name: &str, user: Option<&str>) -> Host {
      let target = Target {
         host: name,
         user,
         local: "me",
      };

      let mut host = Host::default();
      host.apply(text, Path::new("/nonexistent"), target, true, 0);
      host
   }

   /// What `text` says about `name`.
   fn lookup(text: &str, name: &str) -> Host {
      lookup_as(text, name, None)
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

   /// `Match` conditions are checked against what is known when the line
   /// is read, and all of them must hold.
   #[test]
   fn match_conditions() {
      let text = "
         Match user build
            QshPort 1
         Match host *.example.com !localuser root
            QshPort 2
         Host box
            HostName box.example.com
         Match host *.example.com originalhost box
            QshPort 3
         Match exec true
            QshPort 4
         Match all
            QshPort 5
      ";

      let port = |name, user| lookup_as(text, name, user).port;

      assert_eq!(
         port("box", Some("build")).as_deref(),
         Some("1"),
         "the named account"
      );
      assert_eq!(
         port("box", None).as_deref(),
         Some("3"),
         "the name from HostName"
      );
      assert_eq!(
         port("a.example.com", None).as_deref(),
         Some("2"),
         "both conditions"
      );
      assert_eq!(
         port("other", None).as_deref(),
         Some("5"),
         "exec holds for nobody"
      );
   }

   /// `SetEnv` keeps quoted blanks and only its first line, and `SendEnv`
   /// adds up and takes patterns back.
   #[test]
   fn environment_lines() {
      let text = "
         SetEnv COLORTERM=\"truecolor\" NOTE=\"two words\"
         SetEnv LATER=1
         SendEnv LANG LC_*
         SendEnv EDITOR -LC_*
      ";

      let host = lookup(text, "box");

      assert_eq!(
         host.set_env,
         ["COLORTERM=truecolor", "NOTE=two words"],
         "first line, without quotes"
      );
      assert_eq!(host.send_env, ["LANG", "EDITOR"], "pattern taken back");
   }

   /// A negated pattern keeps a host out of a block, and a `Match` block
   /// applies only to whom it names.
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
