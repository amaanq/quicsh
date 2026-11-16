//! Logins that PAM decides, behind one call.
//!
//! This crate holds the unsafe code that calling a C library takes, so that
//! quicsh itself has none.

use std::{
   error::Error,
   ffi::{
      CStr,
      CString,
      c_char,
      c_int,
      c_void,
   },
   fmt,
   ptr,
};

/// `PAM_SUCCESS`.
const SUCCESS: c_int = 0;
/// `PAM_BUF_ERR`.
const BUFFER_ERROR: c_int = 5;
/// `PAM_CONV_ERR`.
const CONVERSATION_ERROR: c_int = 19;
/// `PAM_RHOST`.
const REMOTE_HOST: c_int = 4;
/// `PAM_DISALLOW_NULL_AUTHTOK`, which keeps out an account with an empty
/// password.
const NO_EMPTY_PASSWORD: c_int = 1;
/// `PAM_MAX_NUM_MSG`.
const MAX_MESSAGES: usize = 32;

/// `struct pam_message`.
#[repr(C)]
struct Message {
   style: c_int,
   text:  *const c_char,
}

/// `struct pam_response`.
#[repr(C)]
struct Response {
   text: *mut c_char,
   code: c_int,
}

/// `struct pam_conv`.
#[repr(C)]
struct Conversation {
   callback: extern "C" fn(c_int, *const *const Message, *mut *mut Response, *mut c_void) -> c_int,
   data:     *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
   fn pam_start(
      service: *const c_char,
      user: *const c_char,
      conversation: *const Conversation,
      handle: *mut *mut c_void,
   ) -> c_int;
   fn pam_set_item(handle: *mut c_void, item: c_int, value: *const c_void) -> c_int;
   fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
   fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
   fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
   fn pam_strerror(handle: *mut c_void, code: c_int) -> *const c_char;
}

unsafe extern "C" {
   fn calloc(count: usize, size: usize) -> *mut c_void;
   fn free(memory: *mut c_void);
   fn strdup(text: *const c_char) -> *mut c_char;
}

/// What PAM wants shown to whoever logs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
   /// A question whose answer stays off the screen, such as a password.
   Hidden,
   /// A question whose answer may show.
   Shown,
   /// Something that went wrong, which takes no answer.
   Failure,
   /// Something to read, which takes no answer.
   Notice,
}

impl Style {
   /// The style behind one of PAM's numbers.
   const fn from_number(number: c_int) -> Option<Self> {
      match number {
         1 => Some(Self::Hidden),
         2 => Some(Self::Shown),
         3 => Some(Self::Failure),
         4 => Some(Self::Notice),
         _ => None,
      }
   }

   /// Whether PAM waits for an answer.
   #[must_use]
   pub const fn asks(self) -> bool {
      matches!(self, Self::Hidden | Self::Shown)
   }
}

/// Why PAM let nobody in.
#[derive(Debug)]
pub struct Refusal(String);

impl fmt::Display for Refusal {
   fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str(&self.0)
   }
}

impl Error for Refusal {}

/// What [`login`] calls for each thing PAM wants shown.
type Ask<'ask> = &'ask mut dyn FnMut(Style, &str) -> Option<String>;

/// Overwrites an answer, since most are passwords.
fn wipe(bytes: &mut [u8]) {
   for byte in bytes {
      // SAFETY: the pointer comes from a live exclusive reference.
      unsafe { ptr::write_volatile(byte, 0) };
   }
}

/// Shows one message and returns the copy of its answer that PAM frees,
/// which is null for a message that takes none.
///
/// # Safety
///
/// `message.text` is null or points to a string that ends in a zero byte.
unsafe fn put(ask: Ask<'_>, message: &Message) -> Option<*mut c_char> {
   let style = Style::from_number(message.style)?;

   let text = if message.text.is_null() {
      String::new()
   } else {
      // SAFETY: the caller vouches for the string.
      unsafe { CStr::from_ptr(message.text) }
         .to_string_lossy()
         .into_owned()
   };

   let answer = ask(style, &text);

   if !style.asks() {
      return Some(ptr::null_mut());
   }

   let mut bytes = answer?.into_bytes();
   let terminated = CString::new(bytes.as_slice());
   wipe(&mut bytes);

   let mut held = terminated.ok()?.into_bytes_with_nul();
   // SAFETY: `held` ends in the one zero byte that `CString` added.
   let copy = unsafe { strdup(held.as_ptr().cast()) };
   wipe(&mut held);

   (!copy.is_null()).then_some(copy)
}

/// PAM's conversation function, which hands each message to the [`Ask`]
/// that `data` points to.
extern "C" fn converse(
   count: c_int,
   messages: *const *const Message,
   responses: *mut *mut Response,
   data: *mut c_void,
) -> c_int {
   let Ok(count) = usize::try_from(count) else {
      return CONVERSATION_ERROR;
   };

   if !(1..=MAX_MESSAGES).contains(&count)
      || messages.is_null()
      || responses.is_null()
      || data.is_null()
   {
      return CONVERSATION_ERROR;
   }

   // SAFETY: `login` passes a pointer to an `Ask` that outlives the PAM
   // handle, and PAM calls this function from the thread `login` runs on.
   let ask = unsafe { &mut *data.cast::<Ask<'_>>() };

   // SAFETY: the call takes no pointers.
   let answers = unsafe { calloc(count, size_of::<Response>()) }.cast::<Response>();

   if answers.is_null() {
      return BUFFER_ERROR;
   }

   for index in 0..count {
      // SAFETY: PAM passes `count` pointers, each to a message that lives
      // through this call, and `answers` has room for `count` responses.
      let (message, slot) = unsafe { (&**messages.add(index), &mut *answers.add(index)) };

      // SAFETY: PAM ends each message's text in a zero byte.
      if let Some(copy) = unsafe { put(&mut **ask, message) } {
         slot.text = copy;
         continue;
      }

      for earlier in 0..index {
         // SAFETY: every earlier slot holds null or what `strdup` returned.
         unsafe { free((*answers.add(earlier)).text.cast()) };
      }

      // SAFETY: `calloc` returned the array.
      unsafe { free(answers.cast()) };

      return CONVERSATION_ERROR;
   }

   // SAFETY: PAM passes a place for the array, which it frees.
   unsafe { *responses = answers };

   SUCCESS
}

/// Asks the PAM service whether `user` may log in from `remote`. `ask` gets
/// every question and notice, and returning `None` to a question ends the
/// login.
///
/// # Errors
///
/// Fails when PAM refuses the login, or the account, or cannot start.
pub fn login(
   service: &str,
   user: &str,
   remote: &str,
   mut ask: impl FnMut(Style, &str) -> Option<String>,
) -> Result<(), Refusal> {
   let named =
      |text: &str| CString::new(text).map_err(|_| Refusal("a name holds a zero byte".to_owned()));
   let (service, user, remote) = (named(service)?, named(user)?, named(remote)?);

   let mut asking: Ask<'_> = &mut ask;
   let conversation = Conversation {
      callback: converse,
      data:     (&raw mut asking).cast(),
   };
   let mut handle = ptr::null_mut();

   // SAFETY: the three pointers are live, and PAM copies the conversation.
   let started = unsafe {
      pam_start(
         service.as_ptr(),
         user.as_ptr(),
         &raw const conversation,
         &raw mut handle,
      )
   };

   if started != SUCCESS || handle.is_null() {
      return Err(Refusal(format!("PAM did not start, code {started}")));
   }

   // SAFETY: `handle` is what `pam_start` returned, `remote` ends in a zero
   // byte, and `asking` stays in place until `pam_end`.
   let status = unsafe {
      let mut code = pam_set_item(handle, REMOTE_HOST, remote.as_ptr().cast());

      if code == SUCCESS {
         code = pam_authenticate(handle, NO_EMPTY_PASSWORD);
      }

      if code == SUCCESS {
         code = pam_acct_mgmt(handle, NO_EMPTY_PASSWORD);
      }

      code
   };

   let refusal = (status != SUCCESS).then(|| {
      // SAFETY: PAM returns a string that lives as long as the library, or
      // null.
      let reason = unsafe { pam_strerror(handle, status) };

      if reason.is_null() {
         return Refusal(format!("PAM code {status}"));
      }

      // SAFETY: the string ends in a zero byte.
      Refusal(
         unsafe { CStr::from_ptr(reason) }
            .to_string_lossy()
            .into_owned(),
      )
   });

   // SAFETY: `handle` is live and is not used again.
   unsafe { pam_end(handle, status) };

   refusal.map_or(Ok(()), Err)
}
