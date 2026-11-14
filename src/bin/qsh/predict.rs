//! Shows what the user types before the server echoes it.
//!
//! A terminal emulator follows the session's output, so the cursor and the
//! cells around it are known. A typed character is drawn at the cursor, over
//! what the cell there holds, and before the next output is written the
//! cell gets its character back. The output then draws the real thing. Nothing
//! is drawn until the server echoed a character typed since the last key that
//! is no character, so a password prompt and an editor's command keys show
//! nothing.

use std::{
   cmp::Ordering,
   collections::{
      BTreeMap,
      VecDeque,
   },
   fmt::{
      self,
      Display,
      Formatter,
   },
   fs::File,
   io::{
      self,
      Write,
   },
   mem::take,
   os::fd::{
      AsFd,
      BorrowedFd,
   },
   str::FromStr,
   sync::{
      Arc,
      Mutex,
   },
   time::{
      Duration,
      Instant,
   },
};

use misstep::{
   Report,
   Result,
   bail,
};
use quicsh::control::Size;
use quicsh_vt::Terminal;
use rustix::event::{
   PollFd,
   PollFlags,
   poll,
};

/// Most characters shown ahead of their echo.
const LIMIT: usize = 64;
/// An echo slower than this makes typed characters show early.
const SLOW: Duration = Duration::from_millis(30);
/// An echo faster than this stops that.
const FAST: Duration = Duration::from_millis(20);
/// A character that waited this long for its echo counts as a slow echo.
const OVERDUE: Duration = Duration::from_millis(100);

/// When typed characters show before their echo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
   /// Whenever the server echoes.
   Always,
   /// While the echo is slow enough to notice.
   #[default]
   Auto,
   /// Never.
   Never,
}

impl FromStr for Mode {
   type Err = Report;

   fn from_str(name: &str) -> Result<Self> {
      match name {
         "always" => Ok(Self::Always),
         "auto" => Ok(Self::Auto),
         "never" => Ok(Self::Never),
         other => bail!("expected always, auto or never, got {other}"),
      }
   }
}

impl Display for Mode {
   fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      formatter.write_str(match *self {
         Self::Always => "always",
         Self::Auto => "auto",
         Self::Never => "never",
      })
   }
}

/// Writes all of `bytes` to a terminal that may not take them at once.
fn put(mut screen: &File, bytes: &[u8]) {
   let mut rest = bytes;

   while !rest.is_empty() {
      match screen.write(rest) {
         Ok(count @ 1..) => rest = &rest[count..],
         Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
         Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            let _ = poll(&mut [PollFd::new(&screen, PollFlags::OUT)], None);
         },
         Ok(0) | Err(_) => return,
      }
   }
}

/// A key this side knows the usual echo of.
#[derive(Clone, Copy)]
enum Key {
   /// A character, which goes to the cursor's cell.
   Character(u8),
   /// The backspace key, which empties the cell before the cursor.
   Erase,
}

/// A typed key whose echo has not arrived.
struct Guess {
   /// The key.
   key:   Key,
   /// When it was typed.
   typed: Instant,
   /// The run of typed keys it belongs to.
   run:   u32,
}

/// What the cursor's row looks like once the server echoed some keys.
struct Outcome {
   /// The cursor's column.
   column: usize,
   /// The cells that changed, by column. `None` is an emptied cell, which
   /// the server may fill with what stood to the right of it.
   cells:  BTreeMap<usize, Option<u8>>,
}

/// What is drawn on the terminal ahead of the server.
struct Shown {
   /// The first column drawn over.
   low:    usize,
   /// What the cells from there held.
   held:   Vec<u8>,
   /// Where the cursor was left.
   column: usize,
}

/// The escape sequence that moves the cursor along its row.
fn shift(from: usize, to: usize) -> Vec<u8> {
   match to.cmp(&from) {
      Ordering::Less => format!("\x1b[{}D", from - to).into_bytes(),
      Ordering::Equal => Vec::new(),
      Ordering::Greater => format!("\x1b[{}C", to - from).into_bytes(),
   }
}

/// Follows a session's terminal and draws typed characters on it early.
pub struct Predictor {
   /// What the terminal shows without the early characters.
   terminal: Terminal,
   /// The terminal's width.
   columns:  u16,
   /// The terminal itself.
   screen:   File,
   /// When to draw.
   mode:     Mode,
   /// Keys waiting for their echo.
   pending:  VecDeque<Guess>,
   /// Where the cursor was when the first of them was typed.
   anchor:   (u16, u16),
   /// Where the line being typed starts, when that is known. A backspace
   /// there does nothing.
   floor:    Option<(u16, u16)>,
   /// Whether the last key that is no character started an empty line.
   fresh:    bool,
   /// What is drawn of them.
   shown:    Option<Shown>,
   /// The current run of typed characters. A key that is no character and
   /// a wrong guess start a new one.
   run:      u32,
   /// The last run the server echoed a character of.
   echoed:   Option<u32>,
   /// Whether a key was sent whose effect on the cursor is unknown, so
   /// that no more guesses are made until the pending ones are settled.
   blind:    bool,
   /// Whether the echo is slow.
   slow:     bool,
   /// The smoothed time an echo takes.
   delay:    Duration,
}

impl Predictor {
   /// A predictor for the terminal `screen` of `size`. `None` means there
   /// was no memory for the emulator.
   pub fn new(mode: Mode, size: Size, screen: File) -> Option<Self> {
      Some(Self {
         terminal: Terminal::new(size.columns, size.rows, 0)?,
         columns: size.columns,
         screen,
         mode,
         pending: VecDeque::new(),
         anchor: (0, 0),
         floor: None,
         fresh: false,
         shown: None,
         run: 0,
         echoed: None,
         blind: false,
         slow: false,
         delay: Duration::ZERO,
      })
   }

   /// Starts a new run with nothing pending. What is drawn stays for the
   /// server's output to replace.
   fn restart(&mut self) {
      self.pending.clear();
      self.floor = None;
      self.shown = None;
      self.run = self.run.wrapping_add(1);
      self.blind = false;
   }

   /// Notes a new terminal size.
   pub fn resize(&mut self, size: Size) {
      self.terminal.resize(size.columns, size.rows);
      self.columns = size.columns;
      self.restart();
   }

   /// The row after the first `count` pending keys, unless they lead off
   /// the row.
   fn outcome(&self, count: usize) -> Option<Outcome> {
      let mut column = usize::from(self.anchor.0);
      let mut cells = BTreeMap::new();

      for guess in self.pending.iter().take(count) {
         match guess.key {
            Key::Character(character) => {
               cells.insert(column, Some(character));
               column += 1;
            },
            Key::Erase => {
               let start = self.floor.is_some_and(|floor| {
                  floor == (u16::try_from(column).unwrap_or(0), self.anchor.1)
               });

               if !start {
                  column = column.checked_sub(1)?;
                  cells.insert(column, None);
               }
            },
         }
      }

      (column + 1 < usize::from(self.columns)).then_some(Outcome { column, cells })
   }

   /// Takes what the user typed, which goes to the server as it is.
   pub fn typed(&mut self, input: &[u8]) {
      let now = Instant::now();

      for &byte in input {
         let key = match byte {
            0x20..=0x7E => Some(Key::Character(byte)),
            0x7F => Some(Key::Erase),
            _ => None,
         };

         if let Some(known) = key.filter(|_| !self.blind && self.pending.len() < LIMIT) {
            if self.pending.is_empty() {
               self.anchor = self.terminal.cursor();
            }

            if take(&mut self.fresh) {
               self.floor = Some(self.anchor);
            }

            self.pending.push_back(Guess {
               key:   known,
               typed: now,
               run:   self.run,
            });

            if self.outcome(self.pending.len()).is_some() {
               continue;
            }

            self.pending.pop_back();
         }

         self.run = self.run.wrapping_add(1);
         self.blind = !self.pending.is_empty();
         self.fresh = matches!(byte, b'\r' | 0x03 | 0x15);
         self.floor = None;

         // What follows an escape character in one read is the rest of a
         // key's sequence, of a terminal's answer or of pasted text.
         if byte == 0x1B {
            break;
         }
      }

      if self
         .pending
         .front()
         .is_some_and(|guess| now.duration_since(guess.typed) > OVERDUE)
      {
         self.slow = true;
      }

      self.hide();
      self.draw();
   }

   /// The character in a cell of the cursor's row.
   fn cell(&self, column: usize) -> u32 {
      u16::try_from(column).map_or(0, |place| self.terminal.cell(place, self.anchor.1))
   }

   /// Draws what the pending keys do, unless the server has not echoed in
   /// this run, the echo is fast, the terminal is in the middle of an
   /// escape sequence or a cell holds what this side cannot put back.
   fn draw(&mut self) {
      let wanted = match self.mode {
         Mode::Always => true,
         Mode::Auto => self.slow,
         Mode::Never => false,
      };

      let trusted = self
         .pending
         .back()
         .is_some_and(|guess| Some(guess.run) == self.echoed);

      if !wanted || !trusted || self.shown.is_some() || !self.terminal.unfinished().is_empty() {
         return;
      }

      let Some(outcome) = self.outcome(self.pending.len()) else {
         return;
      };

      let anchor = usize::from(self.anchor.0);
      let low = outcome
         .cells
         .keys()
         .next()
         .map_or(anchor, |&first| first.min(anchor));
      let high = outcome
         .cells
         .keys()
         .next_back()
         .map_or(anchor, |&last| (last + 1).max(anchor));

      let mut held = Vec::new();
      let mut text = shift(anchor, low);

      for column in low..high {
         let under = match self.cell(column) {
            0 => b' ',
            character @ 0x20..=0x7E => u8::try_from(character).unwrap_or(b' '),
            _ => return,
         };

         held.push(under);
         text.push(match outcome.cells.get(&column) {
            Some(&Some(character)) => character,
            Some(&None) => b' ',
            None => under,
         });
      }

      text.extend(shift(high, outcome.column));
      put(&self.screen, &text);

      self.shown = Some(Shown {
         low,
         held,
         column: outcome.column,
      });
   }

   /// Gives the cells that were drawn over their own back, in the style
   /// the session writes in now, and puts the cursor where the session's
   /// output expects it.
   fn hide(&mut self) {
      let Some(shown) = self.shown.take() else {
         return;
      };

      let high = shown.low + shown.held.len();

      let text = [
         shift(shown.column, shown.low),
         shown.held,
         shift(high, usize::from(self.anchor.0)),
      ]
      .concat();

      put(&self.screen, &text);
   }

   /// Whether the terminal shows what the first `count` pending keys do.
   /// Keys that leave the cursor where it was are not told from no echo.
   fn echoed(&self, count: usize, cursor: (u16, u16)) -> bool {
      cursor.1 == self.anchor.1
         && cursor.0 != self.anchor.0
         && self.outcome(count).is_some_and(|outcome| {
            outcome.column == usize::from(cursor.0)
               && outcome.cells.iter().all(|(&column, &cell)| {
                  cell.is_none_or(|character| self.cell(column) == u32::from(character))
               })
         })
   }

   /// Follows session output that was written to the terminal, and settles
   /// the pending keys it echoes.
   fn output(&mut self, bytes: &[u8]) {
      self.terminal.write(bytes);

      let cursor = self.terminal.cursor();

      let settled = (1..=self.pending.len())
         .rev()
         .find(|&count| self.echoed(count, cursor));

      if let Some(last) = settled.and_then(|count| self.pending.drain(..count).next_back()) {
         let sample = last.typed.elapsed();

         self.delay = if self.delay.is_zero() {
            sample
         } else {
            (self.delay * 3 + sample) / 4
         };
         self.slow = self.delay > SLOW || (self.slow && self.delay > FAST);

         if cursor.0 > self.anchor.0 {
            self.echoed = Some(last.run);
         }

         self.anchor = cursor;
      }

      if self.pending.is_empty() {
         self.blind = false;
      } else if cursor != self.anchor {
         self.restart();
      }

      self.draw();
   }
}

/// A terminal that session output is written to, with a predictor that
/// follows it.
pub struct Screen {
   /// The terminal.
   sink:      File,
   /// Draws typed characters early.
   predictor: Arc<Mutex<Predictor>>,
}

impl Screen {
   /// Output for the terminal `sink` that `predictor` follows.
   pub const fn new(sink: File, predictor: Arc<Mutex<Predictor>>) -> Self {
      Self { sink, predictor }
   }
}

impl Write for Screen {
   fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
      let Ok(mut predictor) = self.predictor.lock() else {
         return self.sink.write(bytes);
      };

      predictor.hide();

      let count = self.sink.write(bytes)?;
      predictor.output(&bytes[..count]);

      Ok(count)
   }

   fn flush(&mut self) -> io::Result<()> {
      Ok(())
   }
}

impl AsFd for Screen {
   fn as_fd(&self) -> BorrowedFd<'_> {
      self.sink.as_fd()
   }
}

#[cfg(test)]
mod tests {
   use std::{
      fs::File,
      io::{
         self,
         PipeReader,
         Read as _,
      },
      os::fd::OwnedFd,
   };

   use quicsh::control::Size;
   use rustix::io::ioctl_fionbio;

   use crate::predict::{
      Mode,
      Predictor,
   };

   /// What was drawn on the terminal since the last call.
   fn drawn(screen: &mut PipeReader) -> Vec<u8> {
      let mut bytes = vec![0; 256];
      let count = screen.read(&mut bytes).unwrap_or(0);

      bytes.truncate(count);
      bytes
   }

   /// A character shows early only after the server echoed one typed since
   /// the last key that is no character, and is taken back for the output.
   #[test]
   fn characters_show_once_the_server_echoes() {
      let (mut screen, sink) = io::pipe().expect("a pipe");
      ioctl_fionbio(&screen, true).expect("a pipe that does not block");

      let size = Size {
         columns: 80,
         rows:    24,
      };
      let mut predictor =
         Predictor::new(Mode::Always, size, File::from(OwnedFd::from(sink))).expect("an emulator");

      predictor.output(b"$ ");
      predictor.typed(b"l");
      assert_eq!(drawn(&mut screen), b"", "before any echo");

      predictor.hide();
      predictor.output(b"l");
      predictor.typed(b"s");
      assert_eq!(drawn(&mut screen), b"s", "after an echo");

      predictor.hide();
      assert_eq!(drawn(&mut screen), b"\x1b[1D \x1b[1D", "taken back");

      predictor.output(b"s");
      predictor.typed(b"\x7f");
      assert_eq!(drawn(&mut screen), b"\x1b[1D \x1b[1D", "a backspace");

      predictor.hide();
      drawn(&mut screen);
      predictor.output(b"\x08 \x08");
      predictor.typed(b"\r");
      predictor.output(b"\r\nPassword: ");
      predictor.typed(b"x");
      assert_eq!(drawn(&mut screen), b"", "after the enter key");

      predictor.typed(b"\r");
      predictor.output(b"\r\n$ ");
      predictor.typed(b"a");
      predictor.output(b"a");
      predictor.typed(b"\x7f");
      predictor.hide();
      drawn(&mut screen);
      predictor.output(b"\x08 \x08");
      predictor.typed(b"\x7fb");
      assert_eq!(drawn(&mut screen), b"b", "a backspace on an empty line");
   }
}
