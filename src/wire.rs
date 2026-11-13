//! SSH wire encoding (RFC 4251 section 5), shared by key blobs, signatures,
//! the agent protocol and the control stream.

use crate::error::Error;

pub struct Reader<'bytes>(&'bytes [u8]);

impl<'bytes> Reader<'bytes> {
   #[must_use]
   pub const fn new(bytes: &'bytes [u8]) -> Self {
      Self(bytes)
   }

   #[must_use]
   pub const fn is_empty(&self) -> bool {
      self.0.is_empty()
   }

   fn take(&mut self, count: usize) -> Result<&'bytes [u8], Error> {
      let (head, tail) = self.0.split_at_checked(count).ok_or(Error::Truncated)?;
      self.0 = tail;
      Ok(head)
   }

   /// # Errors
   ///
   /// Fails when no byte is left.
   pub fn byte(&mut self) -> Result<u8, Error> {
      Ok(self.take(1)?[0])
   }

   /// # Errors
   ///
   /// Fails when fewer than four bytes are left.
   pub fn u32(&mut self) -> Result<u32, Error> {
      let bytes = self.take(4)?;
      Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
   }

   /// # Errors
   ///
   /// Fails when the length prefix runs past the end of the input.
   pub fn string(&mut self) -> Result<&'bytes [u8], Error> {
      let length = usize::try_from(self.u32()?).map_err(|_| Error::Truncated)?;
      self.take(length)
   }

   /// # Errors
   ///
   /// Fails when the field is missing or has a different length.
   pub fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], Error> {
      self.string()?.try_into().map_err(|_| Error::Truncated)
   }
}

/// # Panics
///
/// Panics when `bytes` is longer than `u32::MAX` bytes.
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
   let length = u32::try_from(bytes.len()).expect("wire strings stay below 4 GiB");
   out.extend_from_slice(&length.to_be_bytes());
   out.extend_from_slice(bytes);
}
