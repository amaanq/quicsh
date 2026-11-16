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

/// Whether a cell that holds `code` is empty or holds a character that is
/// one cell wide and stands alone, which leaves out the marks that join the
/// character before them.
const fn plain(code: u32) -> bool {
   matches!(code, 0 | 0x20..=0x7E | 0xA1..=0xAC | 0xAE..=0x24F | 0x370..=0x482 | 0x48A..=0x52F)
}

/// Whether `code` is a character every terminal draws two cells wide, which
/// leaves out emoji.
const fn wide(code: u32) -> bool {
   matches!(code, 0x3041..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xAC00..=0xD7A3 | 0xFF01..=0xFF60)
}

/// A key this side knows the usual echo of.
#[derive(Clone, Copy)]
enum Key {
   /// A character, which goes to the cursor's cell.
   Character(char),
   /// The backspace key, which empties the cell before the cursor.
   Erase,
   /// The left arrow.
   Left,
   /// The right arrow.
   Right,
   /// The key that goes to the start of the line.
   Home,
   /// The key that goes to the end of the line.
   End,
   /// The key that removes the character under the cursor.
   Delete,
   /// The key that removes the rest of the line.
   Kill,
}

impl Key {
   /// The key that `input` starts with and how many bytes it takes, as a
   /// shell with the usual bindings reads them.
   const fn read(input: &[u8]) -> Option<(Self, usize)> {
      Some(match *input {
         [byte @ 0x20..=0x7E, ..] => (Self::Character(byte as char), 1),
         [lead @ 0xC2..=0xDF, next @ 0x80..=0xBF, ..] => {
            let code = ((lead as u32 & 0x1F) << 6) | (next as u32 & 0x3F);

            match char::from_u32(code) {
               Some(character) if plain(code) => (Self::Character(character), 2),
               _ => return None,
            }
         },
         [
            lead @ 0xE0..=0xEF,
            next @ 0x80..=0xBF,
            last @ 0x80..=0xBF,
            ..,
         ] => {
            let code =
               ((lead as u32 & 0x0F) << 12) | ((next as u32 & 0x3F) << 6) | (last as u32 & 0x3F);

            match char::from_u32(code) {
               Some(character) if wide(code) => (Self::Character(character), 3),
               _ => return None,
            }
         },
         [0x7F, ..] => (Self::Erase, 1),
         [0x01, ..] => (Self::Home, 1),
         [0x02, ..] => (Self::Left, 1),
         [0x05, ..] => (Self::End, 1),
         [0x06, ..] => (Self::Right, 1),
         [0x0B, ..] => (Self::Kill, 1),
         [0x1B, b'[' | b'O', b'D', ..] => (Self::Left, 3),
         [0x1B, b'[' | b'O', b'C', ..] => (Self::Right, 3),
         [0x1B, b'[' | b'O', b'H', ..] => (Self::Home, 3),
         [0x1B, b'[' | b'O', b'F', ..] => (Self::End, 3),
         [0x1B, b'[', b'1' | b'7', b'~', ..] => (Self::Home, 4),
         [0x1B, b'[', b'4' | b'8', b'~', ..] => (Self::End, 4),
         [0x1B, b'[', b'3', b'~', ..] => (Self::Delete, 4),
         _ => return None,
      })
   }
}

/// The line the user types, for one that began empty and that only keys
/// with a known echo changed since.
#[derive(Clone, Copy)]
struct Line {
   /// The row it is on.
   row:   u16,
   /// The column it starts at. A backspace and a left arrow there do
   /// nothing.
   floor: usize,
   /// The column after its last character. A character typed before it
   /// moves the rest of the line.
   end:   usize,
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
   cells:  BTreeMap<usize, Option<char>>,
   /// The column after the line's last character, when the line is known.
   end:    Option<usize>,
}

/// What is drawn on the terminal ahead of the server.
struct Shown {
   /// The first column drawn over.
   low:    usize,
   /// How many cells from there may be drawn over.
   width:  usize,
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

/// Whether `input` starts with what a terminal answers a program's question
/// with, such as where the cursor is. A shell may ask at every prompt, and
/// the answer is no key.
fn answer(input: &[u8]) -> bool {
   match *input {
      [0x1B, b']' | b'P' | b'_', ..] | [0x1B, b'[', b'?' | b'>', ..] => true,
      [0x1B, b'[', ref rest @ ..] => {
         let last = rest.iter().find(|&&byte| matches!(byte, 0x40..=0x7E));
         last.is_some_and(|byte| b"Rcnty".contains(byte))
      },
      _ => false,
   }
}

/// How many bytes at the start of `input` are such an answer in the form
/// that ends with a letter, or 0.
pub fn answered(input: &[u8]) -> usize {
   match *input {
      [0x1B, b'[', ref rest @ ..] if answer(input) => {
         rest
            .iter()
            .position(|&byte| matches!(byte, 0x40..=0x7E))
            .map_or(0, |last| last + 3)
      },
      _ => 0,
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
   /// The line being typed as it was then, when that is known.
   line:     Option<Line>,
   /// The characters of that line, which the pending keys move.
   text:     Vec<u32>,
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
         line: None,
         text: Vec::new(),
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
      self.line = None;
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

   /// Notes what the known line and the cell after it hold, before any
   /// pending key changes them. The emulator shows the line with their echo
   /// later, when the keys are still compared with it.
   fn note(&mut self) {
      let line = self.line.map_or(0..0, |known| known.floor..known.end + 1);

      self.text = line.map(|column| self.cell(column)).collect();
   }

   /// What a cell of the known line holds once `cells` are drawn over it,
   /// which is 0 for an empty cell, unless that is no plain character.
   fn under(&self, cells: &BTreeMap<usize, Option<char>>, column: usize) -> Option<u32> {
      let noted = || {
         let place = column.checked_sub(self.line?.floor)?;
         self.text.get(place).copied()
      };

      match cells.get(&column) {
         Some(&drawn) => Some(drawn.map_or(0, u32::from)),
         None => Some(noted().unwrap_or(0)).filter(|&held| plain(held)),
      }
   }

   /// Whether `column` is the right half of a wide character, an empty cell
   /// that no key stops on.
   fn split(&self, column: usize) -> bool {
      column
         .checked_sub(1)
         .is_some_and(|before| wide(self.cell(before)))
   }

   /// The row after the first `count` pending keys, unless they lead off
   /// the row or move what this side cannot draw. A wide character is
   /// guessed only at the end of a known line, where a terminal that draws
   /// it narrower moves nothing else.
   fn outcome(&self, count: usize) -> Option<Outcome> {
      let line = self.line.filter(|line| line.row == self.anchor.1);
      let floor = line.map(|known| known.floor);

      // A shell that shows a suggestion after the line takes it when the
      // cursor is sent right from the end.
      let suggested = line.is_some_and(|known| {
         self
            .text
            .get(known.end - known.floor)
            .is_some_and(|&next| next != 0)
      });

      let mut end = line.map(|known| known.end);
      let mut column = usize::from(self.anchor.0);
      let mut cells = BTreeMap::new();
      let mut widened = false;

      for guess in self.pending.iter().take(count) {
         let width = match guess.key {
            Key::Character(character) => 1 + usize::from(wide(u32::from(character))),
            _ if widened => return None,
            _ => 1,
         };

         if width == 2 && end != Some(column) {
            return None;
         }

         match guess.key {
            Key::Character(character) => {
               for place in (column..end.unwrap_or(column)).rev() {
                  let moved = self.under(&cells, place)?;
                  cells.insert(
                     place + 1,
                     char::from_u32(moved).filter(|&held| held != '\0'),
                  );
               }

               cells.insert(column, Some(character));
               column += width;
               end = end.map(|last| (last + 1).max(column));
               widened |= width == 2;
            },
            Key::Erase if floor == Some(column) => {},
            Key::Delete if end.is_none_or(|last| column >= last) => {},
            key @ (Key::Erase | Key::Delete) => {
               if matches!(key, Key::Erase) {
                  column = column.checked_sub(1)?;
               }

               if wide(self.cell(column)) || self.split(column) {
                  return None;
               }

               let last = end.unwrap_or(column + 1).max(column + 1);

               for place in column + 1..last {
                  let moved = self.under(&cells, place)?;
                  cells.insert(
                     place - 1,
                     char::from_u32(moved).filter(|&held| held != '\0'),
                  );
               }

               cells.insert(last - 1, None);
               end = end.map(|_| last - 1);
            },
            Key::Kill => {
               cells.extend((column..end.unwrap_or(column)).map(|place| (place, None)));
               end = end.map(|_| column);
            },
            Key::Left => column -= usize::from(floor.is_some_and(|start| column > start)),
            Key::Right if end.is_some_and(|last| column < last) => column += 1,
            Key::Right | Key::End if suggested => return None,
            Key::Right => {},
            Key::Home => column = floor.unwrap_or(column),
            Key::End => column = end.unwrap_or(column),
         }

         if !widened && self.split(column) {
            return None;
         }
      }

      (end.unwrap_or(column).max(column) + 1 < usize::from(self.columns)).then_some(Outcome {
         column,
         cells,
         end,
      })
   }

   /// Takes what the user typed, which goes to the server as it is.
   pub fn typed(&mut self, input: &[u8]) {
      let now = Instant::now();
      let mut rest = input;

      while let Some((&byte, after)) = rest.split_first().filter(|_| !answer(rest)) {
         // Only a character and a backspace have a known echo on a line
         // whose start and end are not known.
         let read = Key::read(rest).filter(|read| {
            matches!(read.0, Key::Character(_) | Key::Erase) || self.line.is_some() || self.fresh
         });

         rest = read.map_or(after, |(_, length)| rest.get(length..).unwrap_or_default());

         let key = read.map(|(key, _)| key);

         if let Some(known) = key.filter(|_| !self.blind && self.pending.len() < LIMIT) {
            if self.pending.is_empty() {
               self.anchor = self.terminal.cursor();
            }

            if take(&mut self.fresh) {
               self.line = Some(Line {
                  row:   self.anchor.1,
                  floor: usize::from(self.anchor.0),
                  end:   usize::from(self.anchor.0),
               });
            }

            if self.pending.is_empty() {
               self.note();
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
         self.line = None;

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

   /// Draws what the pending keys do, in the style the session writes in,
   /// unless the server has not echoed in this run, the echo is fast, the
   /// terminal is in the middle of an escape sequence or a cell holds what
   /// this side cannot put back.
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
      let mut place = anchor;
      let mut text = Vec::new();

      for (&column, &cell) in &outcome.cells {
         let character = cell.unwrap_or(' ');
         let width = 1 + usize::from(wide(u32::from(character)));

         if !(column..column + width).all(|covered| plain(self.cell(covered))) {
            return;
         }

         text.extend(shift(place, column));
         text.extend(character.encode_utf8(&mut [0; 4]).bytes());
         place = column + width;

         // The terminal may count the character's width another way, and
         // the moves that follow are relative.
         if width == 2 {
            text.extend(format!("\x1b[{}G", place + 1).bytes());
         }
      }

      text.extend(shift(place, outcome.column));
      put(&self.screen, &text);

      let low = outcome.cells.keys().next().copied().unwrap_or(anchor);

      self.shown = Some(Shown {
         low,
         width: outcome
            .cells
            .iter()
            .next_back()
            .map_or(0, |(&last, &cell)| {
               last + 1 + usize::from(cell.is_some_and(|held| wide(u32::from(held)))) - low
            }),
         column: outcome.column,
      });
   }

   /// Gives the cells that were drawn over their own back, in their own
   /// styles, and puts the cursor where the session's output expects it.
   fn hide(&mut self) {
      let Some(shown) = self.shown.take() else {
         return;
      };

      let anchor = usize::from(self.anchor.0);
      let high = shown.low + shown.width;
      let last = (shown.low..high)
         .rev()
         .find(|&column| self.cell(column) != 0);

      let held = u16::try_from(shown.low)
         .ok()
         .zip(u16::try_from(last.unwrap_or(shown.low)).ok())
         .filter(|_| shown.width > 0);

      // The emulator leaves out the empty cells at the end, so all of the
      // cells are emptied first. Its text ends with the session's style.
      let text = match held {
         Some((first, end)) => {
            [
               shift(shown.column, shown.low),
               b"\x1b[0m".to_vec(),
               vec![b' '; shown.width],
               shift(high, shown.low),
               self.terminal.cells(self.anchor.1, first, end),
               shift(last.map_or(shown.low, |column| column + 1), anchor),
            ]
            .concat()
         },
         None => shift(shown.column, anchor),
      };

      put(&self.screen, &text);
   }

   /// Whether the terminal shows what the first `count` pending keys do.
   /// Keys that leave the cursor where it was and put no other character
   /// in a cell are not told from no echo.
   fn echoed(&self, count: usize, cursor: (u16, u16)) -> bool {
      let unchanged = BTreeMap::new();

      cursor.1 == self.anchor.1
         && self.outcome(count).is_some_and(|outcome| {
            let mut placed = outcome
               .cells
               .iter()
               .filter_map(|(&column, &cell)| Some((column, cell?)));

            outcome.column == usize::from(cursor.0)
               && placed
                  .clone()
                  .all(|(column, character)| self.cell(column) == u32::from(character))
               && (cursor.0 != self.anchor.0
                  || placed.any(|(column, character)| {
                     self.under(&unchanged, column) != Some(u32::from(character))
                  }))
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

      let end = settled
         .and_then(|count| self.outcome(count))
         .and_then(|outcome| outcome.end);

      if let (Some(line), Some(last)) = (self.line.as_mut(), end) {
         line.end = last;
      }

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
         self.note();
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

   /// A predictor that always draws, and what it draws on.
   fn started() -> (PipeReader, Predictor) {
      let (screen, sink) = io::pipe().expect("a pipe");
      ioctl_fionbio(&screen, true).expect("a pipe that does not block");

      let size = Size {
         columns: 80,
         rows:    24,
      };
      let predictor =
         Predictor::new(Mode::Always, size, File::from(OwnedFd::from(sink))).expect("an emulator");

      (screen, predictor)
   }

   /// A character shows early only after the server echoed one typed since
   /// the last key that is no character, and is taken back for the output.
   #[test]
   fn characters_show_once_the_server_echoes() {
      let (mut screen, mut predictor) = started();

      predictor.output(b"$ ");
      predictor.typed(b"l");
      assert_eq!(drawn(&mut screen), b"", "before any echo");

      predictor.hide();
      predictor.output(b"l");
      predictor.typed(b"s");
      assert_eq!(drawn(&mut screen), b"s", "after an echo");

      predictor.hide();
      assert_eq!(
         drawn(&mut screen),
         b"\x1b[1D\x1b[0m \x1b[1D\x1b[0m",
         "taken back"
      );

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

      predictor.hide();
      drawn(&mut screen);
      predictor.output(b"b\x1b[90mcd\x1b[39m\x1b[2D");
      predictor.typed(b"e");
      drawn(&mut screen);
      predictor.hide();
      assert_eq!(
         drawn(&mut screen),
         b"\x1b[1D\x1b[0m \x1b[1D\x1b[0m\x1b[38;5;8mc\x1b[0m\x1b[0m\x1b[1D",
         "a covered cell gets its style back"
      );

      predictor.typed(b"\r");
      predictor.output(b"\r\n$ ");
      predictor.typed(b"a");
      predictor.output(b"a");
      drawn(&mut screen);
      predictor.typed(b"c\x1b[D");
      assert_eq!(drawn(&mut screen), b"c\x1b[1D", "a left arrow");

      predictor.typed(b"b");
      assert_eq!(
         drawn(&mut screen),
         b"\x1b[0m \x1b[1D\x1b[0mbc\x1b[1D",
         "a character before the end of the line"
      );

      predictor.hide();
      drawn(&mut screen);
      predictor.output(b"c\x08bc\x08");
      predictor.typed(b"\x7f");
      assert_eq!(
         drawn(&mut screen),
         b"\x1b[1Dc \x1b[2D",
         "a backspace before the end of the line"
      );

      predictor.typed(b"\r");
      predictor.output(b"\r\n$ ");
      predictor.typed(b"a");
      predictor.output(b"a");
      drawn(&mut screen);
      predictor.typed("\u{e9}\u{44f}".as_bytes());
      assert_eq!(
         drawn(&mut screen),
         "\u{e9}\u{44f}".as_bytes(),
         "letters outside ASCII"
      );
   }

   /// A character two cells wide shows early at the end of a line, and a
   /// backspace over one waits for the server.
   #[test]
   fn wide_characters_show_at_the_end_of_a_line() {
      let (mut screen, mut predictor) = started();

      predictor.typed(b"\r");
      predictor.output(b"\r\n$ ");
      predictor.typed(b"a");
      predictor.output(b"a");
      drawn(&mut screen);
      predictor.typed("\u{65e5}".as_bytes());
      assert_eq!(
         drawn(&mut screen),
         "\u{65e5}\x1b[6G".as_bytes(),
         "a wide character at the end of the line"
      );

      predictor.hide();
      assert_eq!(
         drawn(&mut screen),
         b"\x1b[2D\x1b[0m  \x1b[2D\x1b[0m",
         "both of its cells taken back"
      );

      predictor.output("\u{65e5}".as_bytes());
      predictor.typed(b"\x7f");
      assert_eq!(drawn(&mut screen), b"", "no guess for a backspace over it");
   }
}
