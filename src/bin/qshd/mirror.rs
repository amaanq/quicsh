//! The session's terminal as its programs have drawn it.
//!
//! - A client that keeps up gets the session's output byte for byte, and the
//!   mirror only watches.
//! - While the client's link is full, the output goes to the mirror alone, so
//!   the program runs on. Once the link has room, the client gets the screen as
//!   it is by then, and output byte for byte again after it.
//! - A client that lacks output the session no longer keeps gets the history
//!   and the screen in place of that output.

use std::time::{
   Duration,
   Instant,
};

use misstep::{
   OptionExt as _,
   Result,
};
use quicsh::control::Size;
use quicsh_vt::Terminal;

/// Rows of history the mirror keeps above the screen.
const HISTORY: usize = 10_000;
/// The least time between two screens for a client that fell behind.
const FRAME: Duration = Duration::from_millis(16);
/// Ends an escape sequence that the client's terminal may be in the middle
/// of, and holds the drawing back until all of it arrived.
const BEGIN: &[u8] = b"\x18\x1b[?2026h";
/// Shows what was drawn since [`BEGIN`].
const END: &[u8] = b"\x1b[?2026l";
/// Puts the modes a program may have set back to what a new terminal has.
/// The mirror then names the ones that are set now.
const DEFAULTS: &[u8] =
   b"\x1b[!p\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1006l\x1b[?2004l\x1b[=0u";
/// Leaves the alternate screen and clears the main one.
const MAIN: &[u8] = b"\x1b[?1049l\x1b[H\x1b[2J";
/// Enters the alternate screen and clears it. The main screen keeps what
/// the client last saw of it.
const ALTERNATE: &[u8] = b"\x1b[?1049h\x1b[H\x1b[2J";

/// A terminal that follows a session's output.
pub struct Mirror {
   /// The terminal.
   terminal: Terminal,
   /// How many rows the screen has.
   rows:     u16,
   /// Whether the client lacks output that the terminal took.
   behind:   bool,
   /// Whether the client's main screen is older than the last screen it
   /// got, which was the alternate one.
   covered:  bool,
   /// When the client last got a screen.
   sent:     Instant,
}

impl Mirror {
   /// An empty terminal of `size`.
   pub fn new(size: Size, now: Instant) -> Result<Self> {
      Ok(Self {
         terminal: Terminal::new(size.columns, size.rows, HISTORY)
            .context("no memory for the terminal")?,
         rows:     size.rows,
         behind:   false,
         covered:  false,
         sent:     now,
      })
   }

   /// The window title a program in the session set.
   pub fn title(&self) -> String {
      self.terminal.title()
   }

   /// Follows the session's terminal to a new size.
   pub fn resize(&mut self, size: Size) {
      self.terminal.resize(size.columns, size.rows);
      self.rows = size.rows;
   }

   /// Takes output that the client gets as it is. A program that leaves
   /// the alternate screen uncovers the client's main screen, which is
   /// drawn again when it is out of date.
   pub fn watch(&mut self, bytes: &[u8]) {
      self.terminal.write(bytes);
      self.behind = self.covered && !self.terminal.alternate();
   }

   /// Takes output that the client does not get.
   pub fn skip(&mut self, bytes: &[u8]) {
      self.terminal.write(bytes);
      self.behind = true;
   }

   /// Whether output is kept from the client.
   pub const fn skipping(&self) -> bool {
      self.behind
   }

   /// When [`Mirror::frame`] has something to send.
   pub fn due(&self) -> Option<Instant> {
      self.behind.then(|| self.sent + FRAME)
   }

   /// The current screen, for a client that is behind and whose link has
   /// room. The client is up to date with it and takes the output that
   /// follows as it is.
   pub fn frame(&mut self, now: Instant) -> Option<Vec<u8>> {
      if !self.behind || now < self.sent + FRAME {
         return None;
      }

      self.behind = false;
      self.sent = now;

      Some([BEGIN, self.redraw().as_slice()].concat())
   }

   /// What draws the current screen on a terminal in any state, and then
   /// leaves that terminal where this one is in the session's output.
   fn redraw(&mut self) -> Vec<u8> {
      self.covered = self.terminal.alternate();
      let place = if self.covered { ALTERNATE } else { MAIN };

      [
         DEFAULTS,
         place,
         &self.terminal.screen(),
         END,
         &self.terminal.unfinished(),
      ]
      .concat()
   }

   /// The history and the current screen, for a client that has nothing of
   /// the session or lost its place in it.
   pub fn snapshot(&mut self, now: Instant) -> Vec<u8> {
      let history = self.terminal.history();
      let mut text = [BEGIN, DEFAULTS, MAIN].concat();

      // The history goes through the client's screen into its scrollback.
      if !history.is_empty() {
         text.extend_from_slice(&history);
         text.extend_from_slice(b"\x1b[m");
         text.extend_from_slice(&b"\r\n".repeat(self.rows.into()));
      }

      text.extend_from_slice(&self.redraw());

      self.behind = false;
      self.sent = now;

      text
   }
}
