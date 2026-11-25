//! Logins that PAM decides, behind one call.
//!
//! This crate holds the unsafe code that calling a C library takes, so that
//! quicsh itself has none.

#[cfg(target_os = "macos")] use std::io;
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
#[cfg(not(target_os = "macos"))]
const CONVERSATION_ERROR: c_int = 19;
/// `PAM_CONV_ERR` (OpenPAM).
#[cfg(target_os = "macos")]
const CONVERSATION_ERROR: c_int = 6;
/// `PAM_TTY`.
const TERMINAL: c_int = 3;
/// `PAM_RHOST`.
const REMOTE_HOST: c_int = 4;
/// `PAM_ESTABLISH_CRED`.
#[cfg(not(target_os = "macos"))]
const ESTABLISH: c_int = 2;
/// `PAM_ESTABLISH_CRED` (OpenPAM).
#[cfg(target_os = "macos")]
const ESTABLISH: c_int = 1;
/// `PAM_DELETE_CRED`.
#[cfg(not(target_os = "macos"))]
const DELETE: c_int = 4;
/// `PAM_DELETE_CRED` (OpenPAM).
#[cfg(target_os = "macos")]
const DELETE: c_int = 2;
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
   fn pam_setcred(handle: *mut c_void, flags: c_int) -> c_int;
   fn pam_open_session(handle: *mut c_void, flags: c_int) -> c_int;
   fn pam_close_session(handle: *mut c_void, flags: c_int) -> c_int;
   fn pam_getenvlist(handle: *mut c_void) -> *mut *mut c_char;
   fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
   fn pam_strerror(handle: *mut c_void, code: c_int) -> *const c_char;
}

unsafe extern "C" {
   fn calloc(count: usize, size: usize) -> *mut c_void;
   fn free(memory: *mut c_void);
   fn strdup(text: *const c_char) -> *mut c_char;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
   fn initgroups(name: *const c_char, group: c_int) -> c_int;
   fn setgid(group: u32) -> c_int;
   fn setuid(user: u32) -> c_int;
}

/// Switches the process to `name` (`uid`, `gid`) and its supplementary
/// groups via `initgroups`, `setgid`, and `setuid`.
///
/// # Errors
///
/// Fails if `name` contains a NUL byte or any privilege-drop call fails.
#[cfg(target_os = "macos")]
pub fn become_user(name: &str, uid: u32, gid: u32) -> io::Result<()> {
   let text = CString::new(name).map_err(io::Error::other)?;

   // SAFETY: `text` is a valid NUL-terminated C string.
   if unsafe { initgroups(text.as_ptr(), gid.cast_signed()) } != 0 {
      return Err(io::Error::last_os_error());
   }

   // SAFETY: `setgid` and `setuid` take only scalar IDs.
   if unsafe { setgid(gid) } != 0 || unsafe { setuid(uid) } != 0 {
      return Err(io::Error::last_os_error());
   }

   Ok(())
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

/// Shows every message of one round and hands PAM the answers.
///
/// # Safety
///
/// `messages` and `responses` are what PAM passed to a conversation
/// function along with `count`.
unsafe fn exchange(
   count: c_int,
   messages: *const *const Message,
   responses: *mut *mut Response,
   ask: Ask<'_>,
) -> c_int {
   let Ok(count) = usize::try_from(count) else {
      return CONVERSATION_ERROR;
   };

   if !(1..=MAX_MESSAGES).contains(&count) || messages.is_null() || responses.is_null() {
      return CONVERSATION_ERROR;
   }

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
      if let Some(copy) = unsafe { put(&mut *ask, message) } {
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

/// The conversation function of [`login`], which hands each message to the
/// [`Ask`] that `data` points to.
extern "C" fn converse(
   count: c_int,
   messages: *const *const Message,
   responses: *mut *mut Response,
   data: *mut c_void,
) -> c_int {
   if data.is_null() {
      return CONVERSATION_ERROR;
   }

   // SAFETY: `login` passes a pointer to an `Ask` that outlives the PAM
   // handle, and PAM calls this function from the thread `login` runs on.
   let ask = unsafe { &mut *data.cast::<Ask<'_>>() };

   // SAFETY: the three values are PAM's.
   unsafe { exchange(count, messages, responses, &mut **ask) }
}

/// The conversation function where nobody can be asked. Notices pass
/// unseen and a question fails.
extern "C" fn quiet(
   count: c_int,
   messages: *const *const Message,
   responses: *mut *mut Response,
   _data: *mut c_void,
) -> c_int {
   // SAFETY: the three values are PAM's.
   unsafe {
      exchange(count, messages, responses, &mut |style, _| {
         (!style.asks()).then(String::new)
      })
   }
}

/// One use of a PAM service for one user, which ends when this is dropped.
struct Handle {
   raw:    *mut c_void,
   /// What the last PAM call returned, which PAM wants to hear at the end.
   status: c_int,
}

impl Handle {
   /// Starts on the service for `user` at `remote`. PAM copies the
   /// conversation, and whatever its `data` points to must outlive the
   /// handle.
   fn start(
      service: &str,
      user: &str,
      remote: &str,
      conversation: &Conversation,
   ) -> Result<Self, Refusal> {
      let (service, user, remote) = (named(service)?, named(user)?, named(remote)?);
      let mut raw = ptr::null_mut();

      // SAFETY: the pointers are live and PAM copies what they point to.
      let started =
         unsafe { pam_start(service.as_ptr(), user.as_ptr(), conversation, &raw mut raw) };

      if started != SUCCESS || raw.is_null() {
         return Err(Refusal(format!("PAM did not start, code {started}")));
      }

      let mut handle = Self {
         raw,
         status: SUCCESS,
      };

      handle.set(REMOTE_HOST, &remote)?;
      Ok(handle)
   }

   /// Gives PAM one of the strings it keeps about the user.
   fn set(&mut self, item: c_int, value: &CStr) -> Result<(), Refusal> {
      // SAFETY: the handle is live and PAM copies the string.
      self.took(unsafe { pam_set_item(self.raw, item, value.as_ptr().cast()) })
   }

   /// Notes what a PAM call returned and turns a failure into its reason.
   fn took(&mut self, code: c_int) -> Result<(), Refusal> {
      self.status = code;

      if code == SUCCESS {
         return Ok(());
      }

      // SAFETY: PAM returns a string that lives as long as the library, or
      // null.
      let reason = unsafe { pam_strerror(self.raw, code) };

      if reason.is_null() {
         return Err(Refusal(format!("PAM code {code}")));
      }

      // SAFETY: the string ends in a zero byte.
      let text = unsafe { CStr::from_ptr(reason) };
      Err(Refusal(text.to_string_lossy().into_owned()))
   }

   /// The variables PAM's modules want in the user's environment.
   fn environment(&self) -> Vec<(String, String)> {
      // SAFETY: the handle is live.
      let list = unsafe { pam_getenvlist(self.raw) };
      let mut variables = Vec::new();

      if list.is_null() {
         return variables;
      }

      for index in 0.. {
         // SAFETY: the list ends in a null pointer, and nothing reads past
         // it.
         let entry = unsafe { *list.add(index) };

         if entry.is_null() {
            break;
         }

         // SAFETY: each entry ends in a zero byte.
         let text = unsafe { CStr::from_ptr(entry) }.to_string_lossy();

         if let Some((name, value)) = text.split_once('=') {
            variables.push((name.to_owned(), value.to_owned()));
         }

         // SAFETY: the caller of `pam_getenvlist` owns each entry.
         unsafe { free(entry.cast()) };
      }

      // SAFETY: the caller of `pam_getenvlist` owns the list.
      unsafe { free(list.cast()) };

      variables
   }
}

impl Drop for Handle {
   fn drop(&mut self) {
      // SAFETY: the handle is live and is not used again.
      unsafe { pam_end(self.raw, self.status) };
   }
}

/// A name as PAM takes it.
fn named(text: &str) -> Result<CString, Refusal> {
   CString::new(text).map_err(|_| Refusal("a name holds a zero byte".to_owned()))
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
   let mut asking: Ask<'_> = &mut ask;
   let conversation = Conversation {
      callback: converse,
      data:     (&raw mut asking).cast(),
   };

   // `asking` is declared first, so it outlives the handle.
   let mut handle = Handle::start(service, user, remote, &conversation)?;

   // SAFETY: the handle is live.
   handle.took(unsafe { pam_authenticate(handle.raw, NO_EMPTY_PASSWORD) })?;
   // SAFETY: the handle is live.
   handle.took(unsafe { pam_acct_mgmt(handle.raw, NO_EMPTY_PASSWORD) })
}

/// Asks the PAM service whether the account of `user`, who proved who they
/// are in another way, may be used from `remote`.
///
/// # Errors
///
/// Fails when PAM refuses the account, which may be locked or past its
/// end, or cannot start.
pub fn permitted(service: &str, user: &str, remote: &str) -> Result<(), Refusal> {
   let conversation = Conversation {
      callback: quiet,
      data:     ptr::null_mut(),
   };

   let mut handle = Handle::start(service, user, remote, &conversation)?;

   // SAFETY: the handle is live.
   handle.took(unsafe { pam_acct_mgmt(handle.raw, 0) })
}

/// A PAM session, which closes when this is dropped.
pub struct Session(Handle);

impl Session {
   /// Opens a session for `user` in the calling process, which is where
   /// modules set limits and which a login manager then counts as the
   /// session. Returns it with the variables PAM wants in the session's
   /// environment.
   ///
   /// # Errors
   ///
   /// Fails when a module refuses the session or PAM cannot start.
   pub fn open(
      service: &str,
      user: &str,
      remote: &str,
      terminal: Option<&str>,
   ) -> Result<(Self, Vec<(String, String)>), Refusal> {
      let conversation = Conversation {
         callback: quiet,
         data:     ptr::null_mut(),
      };

      let mut handle = Handle::start(service, user, remote, &conversation)?;

      if let Some(device) = terminal {
         handle.set(TERMINAL, &named(device)?)?;
      }

      // The modules that hand out credentials are the ones that check
      // passwords, and they refuse a user who logged in with a key. As in
      // sshd, the session opens without them then.
      // SAFETY: the handle is live.
      unsafe { pam_setcred(handle.raw, ESTABLISH) };
      // SAFETY: the handle is live.
      handle.took(unsafe { pam_open_session(handle.raw, 0) })?;

      let environment = handle.environment();
      Ok((Self(handle), environment))
   }
}

impl Drop for Session {
   fn drop(&mut self) {
      // SAFETY: the handle is live until the field is dropped after this.
      self.0.status = unsafe {
         pam_close_session(self.0.raw, 0);
         pam_setcred(self.0.raw, DELETE)
      };
   }
}
