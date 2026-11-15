//! A terminal emulator that follows a program's output, which is
//! libghostty-vt behind a few calls.
//!
//! This crate holds the unsafe code that calling a C library takes, so that
//! quicsh itself has none.

use std::{
   ffi::c_void,
   ptr::{
      self,
      NonNull,
   },
   slice,
};

unsafe extern "C" {
   fn qvt_new(columns: u16, rows: u16, history: usize) -> *mut c_void;
   fn qvt_free(terminal: *mut c_void);
   fn qvt_write(terminal: *mut c_void, bytes: *const u8, length: usize);
   fn qvt_resize(terminal: *mut c_void, columns: u16, rows: u16) -> bool;
   fn qvt_alternate(terminal: *mut c_void) -> bool;
   fn qvt_history(terminal: *mut c_void) -> usize;
   fn qvt_cursor(terminal: *mut c_void, column: *mut u16, row: *mut u16);
   fn qvt_cell(terminal: *mut c_void, column: u16, row: u16) -> u32;
   fn qvt_format(
      terminal: *mut c_void,
      history: bool,
      out: *mut *mut u8,
      length: *mut usize,
   ) -> bool;
   fn qvt_continuation(terminal: *mut c_void, out: *mut *mut u8, length: *mut usize) -> bool;
   fn qvt_cells(
      terminal: *mut c_void,
      row: u16,
      first: u16,
      last: u16,
      out: *mut *mut u8,
      length: *mut usize,
   ) -> bool;
   fn qvt_title(terminal: *mut c_void, out: *mut u8, limit: usize) -> usize;
   fn qvt_release(bytes: *mut u8, length: usize);
}

/// A terminal with a screen, the history above it and its modes.
pub struct Terminal(NonNull<c_void>);

// SAFETY: the library keeps a terminal's state behind its handle and ties
// none of it to the thread that made it.
unsafe impl Send for Terminal {}

impl Terminal {
   /// A blank terminal that keeps about `history` rows above its screen.
   /// `None` means the library had no memory for it.
   #[must_use]
   pub fn new(columns: u16, rows: u16, history: usize) -> Option<Self> {
      // SAFETY: the call takes no pointers.
      NonNull::new(unsafe { qvt_new(columns.max(1), rows.max(1), history) }).map(Self)
   }

   /// Gives the terminal what a program wrote.
   pub fn write(&mut self, bytes: &[u8]) {
      // SAFETY: the handle is live until drop, and the slice is valid for
      // its length during the call.
      unsafe { qvt_write(self.0.as_ptr(), bytes.as_ptr(), bytes.len()) }
   }

   /// Changes the size of the screen. A size the library cannot take leaves
   /// the screen as it was.
   pub fn resize(&mut self, columns: u16, rows: u16) {
      // SAFETY: the handle is live until drop.
      let _ = unsafe { qvt_resize(self.0.as_ptr(), columns.max(1), rows.max(1)) };
   }

   /// Whether a full-screen program switched to the alternate screen.
   #[must_use]
   pub fn alternate(&self) -> bool {
      // SAFETY: the handle is live until drop.
      unsafe { qvt_alternate(self.0.as_ptr()) }
   }

   /// How many rows of history are above the screen.
   #[must_use]
   pub fn history_rows(&self) -> usize {
      // SAFETY: the handle is live until drop.
      unsafe { qvt_history(self.0.as_ptr()) }
   }

   /// The cursor's column and row on the screen, counted from 0.
   #[must_use]
   pub fn cursor(&self) -> (u16, u16) {
      let (mut column, mut row) = (0, 0);

      // SAFETY: the handle is live, and both pointers are valid for the
      // call.
      unsafe { qvt_cursor(self.0.as_ptr(), &raw mut column, &raw mut row) };

      (column, row)
   }

   /// The character in a cell of the screen, which is 0 for an empty cell
   /// and for a place outside the screen.
   #[must_use]
   pub fn cell(&self, column: u16, row: u16) -> u32 {
      // SAFETY: the handle is live until drop.
      unsafe { qvt_cell(self.0.as_ptr(), column, row) }
   }

   /// The start of the window title a program set, which is empty when
   /// none did.
   #[must_use]
   pub fn title(&self) -> String {
      let mut bytes = [0; 256];

      // SAFETY: the handle is live, and the call writes at most the
      // buffer's length into it.
      let length = unsafe { qvt_title(self.0.as_ptr(), bytes.as_mut_ptr(), bytes.len()) };

      String::from_utf8_lossy(&bytes[..length.min(bytes.len())]).into_owned()
   }

   /// Runs a call that fills a buffer of the library's and copies it out.
   fn copied(&self, fill: impl FnOnce(*mut c_void, *mut *mut u8, *mut usize) -> bool) -> Vec<u8> {
      let mut bytes = ptr::null_mut();
      let mut length = 0;

      if !fill(self.0.as_ptr(), &raw mut bytes, &raw mut length) || bytes.is_null() {
         return Vec::new();
      }

      // SAFETY: the call succeeded, so `bytes` points at `length` bytes the
      // library allocated, which stay until they are released below.
      let copy = unsafe { slice::from_raw_parts(bytes, length) }.to_vec();

      // SAFETY: the buffer came from the library with this length and is
      // not used again.
      unsafe { qvt_release(bytes, length) };

      copy
   }

   /// The escape sequences that draw the screen and set the terminal's
   /// modes, for a terminal whose screen is blank and whose modes are the
   /// defaults.
   #[must_use]
   pub fn screen(&self) -> Vec<u8> {
      // SAFETY: the handle is live, and the out pointers are valid for the
      // call.
      self.copied(|terminal, out, length| unsafe { qvt_format(terminal, false, out, length) })
   }

   /// The rows of history above the screen, with their colors and styles.
   #[must_use]
   pub fn history(&self) -> Vec<u8> {
      // SAFETY: as in `screen`.
      self.copied(|terminal, out, length| unsafe { qvt_format(terminal, true, out, length) })
   }

   /// The escape sequences that draw the cells `first` to `last` of a row
   /// of the screen in their styles, and then set the style the program
   /// writes in.
   #[must_use]
   pub fn cells(&self, row: u16, first: u16, last: u16) -> Vec<u8> {
      // SAFETY: as in `screen`.
      self.copied(|terminal, out, length| unsafe {
         qvt_cells(terminal, row, first, last, out, length)
      })
   }

   /// The start of an escape sequence or of a character that the program
   /// has not finished writing. A terminal that is sent these bytes takes
   /// the rest of the program's output the way this one does.
   #[must_use]
   pub fn unfinished(&self) -> Vec<u8> {
      // SAFETY: as in `screen`.
      self.copied(|terminal, out, length| unsafe { qvt_continuation(terminal, out, length) })
   }
}

impl Drop for Terminal {
   fn drop(&mut self) {
      // SAFETY: the handle came from `qvt_new` and is not used again.
      unsafe { qvt_free(self.0.as_ptr()) }
   }
}

#[cfg(test)]
mod tests {
   use crate::Terminal;

   /// The screen that one terminal draws for another matches, and so does
   /// what follows an escape sequence that was cut in two.
   #[test]
   fn a_second_terminal_follows_the_first() {
      let mut first = Terminal::new(20, 4, 100).expect("a terminal");
      first.write(b"one\r\ntwo\r\n\x1b[31mred\x1b[0m plain\x1b[3");

      let mut second = Terminal::new(20, 4, 100).expect("a terminal");
      second.write(&first.screen());
      second.write(&first.unfinished());

      for terminal in [&mut first, &mut second] {
         terminal.write(b"2mgreen");
      }

      assert_eq!(first.unfinished(), b"", "the sequence ended");
      assert_eq!(
         String::from_utf8_lossy(&second.screen()),
         String::from_utf8_lossy(&first.screen()),
         "both screens"
      );
      assert!(!first.alternate(), "primary screen");
   }

   /// Rows that scroll off the screen are history.
   #[test]
   fn history_holds_what_scrolled_away() {
      let mut terminal = Terminal::new(20, 2, 100).expect("a terminal");
      terminal.write(b"first\r\nsecond\r\nthird\r\nfourth");

      assert_eq!(terminal.history_rows(), 2, "two rows left the screen");

      let history = String::from_utf8_lossy(&terminal.history()).into_owned();
      assert!(
         history.contains("first") && history.contains("second"),
         "{history:?}"
      );
      assert!(!history.contains("third"), "{history:?}");
   }
}
