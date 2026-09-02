//! Hand-written FFI to the system OpenSSL 3.
//!
//! Only the handful of primitives the Tor protocol needs is bound here. Opaque
//! OpenSSL types are all declared as `*mut c_void`; the safe wrappers in the
//! submodules own them and free them in `Drop`, and never hand a raw pointer
//! out. OpenSSL 3 self-initialises on first use, so there is no init call.
//!
//! **The library is loaded at run time, not link time.** Linking with
//! `#[link(name = "ssl")]` would make the linker look for `libssl.so`, the
//! unversioned symlink that only a `-dev`/`-devel` package installs. Deployment
//! containers routinely ship just the runtime `libssl.so.3`, and the project's
//! stated requirement (TASKS.md 0.3) is that the runtime libraries alone are
//! enough. So every entry point is resolved once with `dlopen`/`dlsym`, the
//! binary records no `DT_NEEDED` entry for OpenSSL, and the file name and
//! directory can both vary.
//!
//! Search order for each library, first hit wins:
//!
//! 1. `TOR_LIBSSL` / `TOR_LIBCRYPTO` — an explicit path, if set.
//! 2. `TOR_OPENSSL_DIR` joined with each candidate file name.
//! 3. Each candidate file name on its own, resolved by the dynamic loader.
//! 4. Each candidate file name under the usual library directories, for
//!    containers with no `ld.so.cache`.
//!
//! `OPENSSL_free` and `SSL_set_tlsext_host_name` are macros rather than
//! exported symbols, so they are deliberately not used: buffers are sized with
//! a first `i2d_X509(x, NULL)` call, and no SNI is sent (Tor relays do not want
//! one anyway).

#![allow(non_snake_case)]

use std::ffi::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_void};
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

pub mod aes;
pub mod ed25519;
pub mod hash;
pub mod hmac;
pub mod rand;
pub mod rsa;
pub mod tls;
pub mod x25519;

pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;

/// `SSL_CTX_set_mode` is a macro over `SSL_CTX_ctrl`.
pub const SSL_CTRL_MODE: c_int = 33;
pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x1;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x2;

pub const EVP_PKEY_RSA: c_int = 6;
pub const EVP_PKEY_X25519: c_int = 1034;
pub const EVP_PKEY_ED25519: c_int = 1087;
pub const RSA_PKCS1_PADDING: c_int = 1;

// ---------------------------------------------------------------------------
// Dynamic loading
// ---------------------------------------------------------------------------

// From libdl, which is part of libc on glibc 2.34+ and on musl, and which
// Rust's std already links on every Linux target.
extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *mut c_char;
}

/// Same values on glibc and musl.
const RTLD_NOW: c_int = 2;
const RTLD_GLOBAL: c_int = 0x100;

const LIBSSL_VAR: &str = "TOR_LIBSSL";
const LIBCRYPTO_VAR: &str = "TOR_LIBCRYPTO";
const LIB_DIR_VAR: &str = "TOR_OPENSSL_DIR";

/// OpenSSL 3 first; the unversioned name is what a `-dev` package provides,
/// and 1.1 is listed last only so that finding it produces "this build needs
/// OpenSSL 3" rather than "no library at all".
const LIBSSL_NAMES: &[&str] = &["libssl.so.3", "libssl.so", "libssl.so.1.1"];
const LIBCRYPTO_NAMES: &[&str] = &["libcrypto.so.3", "libcrypto.so", "libcrypto.so.1.1"];

/// Checked only after the dynamic loader's own search fails, for images that
/// ship no `ld.so.cache`.
const SEARCH_DIRS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib64",
    "/usr/lib",
    "/lib64",
    "/lib",
    "/usr/local/lib64",
    "/usr/local/lib",
];

struct Library {
    handle: *mut c_void,
    path: String,
}

/// Declare the OpenSSL entry points once, and generate from that: a struct of
/// function pointers, the code that resolves them, and a safe-to-call shim per
/// symbol with the same name and signature as the old `extern` declaration.
/// Generating all three from one list is the point -- a shim can never drift
/// from the pointer type it calls.
macro_rules! openssl_bindings {
    ($(
        $(#[$attr:meta])*
        fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?;
    )*) => {
        struct Symbols {
            $($(#[$attr])* $name: unsafe extern "C" fn($($ty),*) $(-> $ret)?,)*
            ssl_path: String,
            crypto_path: String,
        }

        impl Symbols {
            unsafe fn resolve_all(ssl: &Library, crypto: &Library) -> Result<Self, String> {
                let handles = [ssl.handle, crypto.handle];
                Ok(Self {
                    $($(#[$attr])* $name: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn($($ty),*) $(-> $ret)?,
                    >(resolve(&handles, concat!(stringify!($name), "\0"))?),)*
                    ssl_path: ssl.path.clone(),
                    crypto_path: crypto.path.clone(),
                })
            }
        }

        $(
            $(#[$attr])*
            #[inline]
            pub unsafe fn $name($($arg: $ty),*) $(-> $ret)? {
                (symbols().$name)($($arg),*)
            }
        )*
    };
}

openssl_bindings! {
    // libssl
    fn TLS_client_method() -> *const c_void;
    fn SSL_CTX_new(method: *const c_void) -> *mut c_void;
    fn SSL_CTX_free(ctx: *mut c_void);
    fn SSL_CTX_ctrl(ctx: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_CTX_set_verify(ctx: *mut c_void, mode: c_int, callback: *const c_void);
    fn SSL_CTX_set_security_level(ctx: *mut c_void, level: c_int);
    fn SSL_new(ctx: *mut c_void) -> *mut c_void;
    fn SSL_free(ssl: *mut c_void);
    fn SSL_set_fd(ssl: *mut c_void, fd: c_int) -> c_int;
    fn SSL_connect(ssl: *mut c_void) -> c_int;
    fn SSL_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_write(ssl: *mut c_void, buf: *const c_void, num: c_int) -> c_int;
    fn SSL_get_error(ssl: *const c_void, ret: c_int) -> c_int;
    fn SSL_shutdown(ssl: *mut c_void) -> c_int;
    fn SSL_get1_peer_certificate(ssl: *const c_void) -> *mut c_void;

    // libcrypto
    fn X509_free(x: *mut c_void);
    fn i2d_X509(x: *const c_void, out: *mut *mut c_uchar) -> c_int;

    fn EVP_sha1() -> *const c_void;
    fn EVP_sha256() -> *const c_void;
    fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut c_uchar,
        size: *mut c_uint,
        md_type: *const c_void,
        engine: *mut c_void,
    ) -> c_int;
    fn EVP_MD_CTX_new() -> *mut c_void;
    fn EVP_MD_CTX_free(ctx: *mut c_void);
    fn EVP_DigestInit_ex(ctx: *mut c_void, md_type: *const c_void, engine: *mut c_void) -> c_int;
    fn EVP_DigestUpdate(ctx: *mut c_void, data: *const c_void, count: usize) -> c_int;
    fn EVP_DigestFinal_ex(ctx: *mut c_void, md: *mut c_uchar, size: *mut c_uint) -> c_int;
    fn EVP_MD_CTX_copy_ex(out: *mut c_void, inp: *const c_void) -> c_int;

    fn HMAC(
        md: *const c_void,
        key: *const c_void,
        key_len: c_int,
        data: *const c_uchar,
        data_len: usize,
        out: *mut c_uchar,
        out_len: *mut c_uint,
    ) -> *mut c_uchar;

    fn EVP_aes_128_ctr() -> *const c_void;
    fn EVP_CIPHER_CTX_new() -> *mut c_void;
    fn EVP_CIPHER_CTX_free(ctx: *mut c_void);
    fn EVP_EncryptInit_ex(
        ctx: *mut c_void,
        cipher: *const c_void,
        engine: *mut c_void,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut c_void,
        out: *mut c_uchar,
        out_len: *mut c_int,
        inp: *const c_uchar,
        in_len: c_int,
    ) -> c_int;

    fn EVP_PKEY_free(pkey: *mut c_void);
    fn EVP_PKEY_get_size(pkey: *const c_void) -> c_int;
    fn EVP_PKEY_CTX_new(pkey: *mut c_void, engine: *mut c_void) -> *mut c_void;
    fn EVP_PKEY_CTX_new_id(id: c_int, engine: *mut c_void) -> *mut c_void;
    fn EVP_PKEY_CTX_free(ctx: *mut c_void);
    fn EVP_PKEY_keygen_init(ctx: *mut c_void) -> c_int;
    fn EVP_PKEY_keygen(ctx: *mut c_void, ppkey: *mut *mut c_void) -> c_int;
    fn EVP_PKEY_get_raw_public_key(
        pkey: *const c_void,
        out: *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_new_raw_public_key(
        key_type: c_int,
        engine: *mut c_void,
        key: *const c_uchar,
        key_len: usize,
    ) -> *mut c_void;
    #[cfg(test)]
    fn EVP_PKEY_new_raw_private_key(
        key_type: c_int,
        engine: *mut c_void,
        key: *const c_uchar,
        key_len: usize,
    ) -> *mut c_void;
    fn EVP_PKEY_derive_init(ctx: *mut c_void) -> c_int;
    fn EVP_PKEY_derive_set_peer(ctx: *mut c_void, peer: *mut c_void) -> c_int;
    fn EVP_PKEY_derive(ctx: *mut c_void, key: *mut c_uchar, key_len: *mut usize) -> c_int;

    fn EVP_DigestVerifyInit(
        ctx: *mut c_void,
        pctx: *mut *mut c_void,
        md_type: *const c_void,
        engine: *mut c_void,
        pkey: *mut c_void,
    ) -> c_int;
    fn EVP_DigestVerify(
        ctx: *mut c_void,
        sig: *const c_uchar,
        sig_len: usize,
        tbs: *const c_uchar,
        tbs_len: usize,
    ) -> c_int;

    fn d2i_PublicKey(
        key_type: c_int,
        a: *mut *mut c_void,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut c_void;
    fn EVP_PKEY_verify_recover_init(ctx: *mut c_void) -> c_int;
    fn EVP_PKEY_verify_recover(
        ctx: *mut c_void,
        out: *mut c_uchar,
        out_len: *mut usize,
        sig: *const c_uchar,
        sig_len: usize,
    ) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut c_void, padding: c_int) -> c_int;

    fn RAND_bytes(buf: *mut c_uchar, num: c_int) -> c_int;

    fn ERR_get_error() -> c_ulong;
    fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
}

static OPENSSL: OnceLock<Result<Symbols, String>> = OnceLock::new();

fn loaded() -> &'static Result<Symbols, String> {
    OPENSSL.get_or_init(|| unsafe { load() })
}

/// Load OpenSSL now and report a readable error if it is missing.
///
/// Call this once at start-up: without it the first cryptographic operation
/// would be the thing that fails, deep inside a worker thread.
pub fn ensure_loaded() -> std::io::Result<()> {
    match loaded() {
        Ok(_) => Ok(()),
        Err(e) => Err(std::io::Error::other(e.clone())),
    }
}

/// The files actually loaded, for the start-up log.
pub fn library_paths() -> Option<(&'static str, &'static str)> {
    loaded()
        .as_ref()
        .ok()
        .map(|s| (s.ssl_path.as_str(), s.crypto_path.as_str()))
}

fn symbols() -> &'static Symbols {
    match loaded() {
        Ok(symbols) => symbols,
        // Unreachable in the binary, which calls ensure_loaded() first.
        Err(e) => panic!("OpenSSL is not loaded: {e}"),
    }
}

unsafe fn load() -> Result<Symbols, String> {
    // libcrypto first, and with RTLD_GLOBAL, so that libssl binds against the
    // copy we chose rather than pulling in a second one.
    let mut tried = Vec::new();
    let crypto = match open_library(LIBCRYPTO_VAR, LIBCRYPTO_NAMES, &mut tried) {
        Some(library) => library,
        None => return Err(not_found("libcrypto", &tried, last_dl_error())),
    };
    let mut tried = Vec::new();
    let ssl = match open_library(LIBSSL_VAR, LIBSSL_NAMES, &mut tried) {
        Some(library) => library,
        None => return Err(not_found("libssl", &tried, last_dl_error())),
    };
    Symbols::resolve_all(&ssl, &crypto)
}

/// Where to look for one library, in order of preference. The explicit
/// per-library override is handled by the caller so that its failure can be
/// reported rather than silently passed over.
fn candidates(names: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(names.len() * (SEARCH_DIRS.len() + 1));
    if let Ok(dir) = std::env::var(LIB_DIR_VAR) {
        let dir = dir.trim_end_matches('/');
        if !dir.is_empty() {
            out.extend(names.iter().map(|name| format!("{dir}/{name}")));
        }
    }
    // A bare name lets the dynamic loader use its own search path.
    out.extend(names.iter().map(|name| (*name).to_string()));
    for dir in SEARCH_DIRS {
        out.extend(names.iter().map(|name| format!("{dir}/{name}")));
    }
    out
}

unsafe fn open_library(env_var: &str, names: &[&str], tried: &mut Vec<String>) -> Option<Library> {
    if let Some(path) = std::env::var(env_var).ok().filter(|p| !p.is_empty()) {
        match try_open(&path) {
            Some(library) => return Some(library),
            None => {
                // Do not fail outright: the setting may be left over from
                // another machine. But never pass over it in silence.
                crate::warn!(
                    "{env_var} is set to {path}, which could not be loaded ({}); \
                     falling back to the usual search",
                    last_dl_error()
                );
                tried.push(path);
            }
        }
    }
    for path in candidates(names) {
        if let Some(library) = try_open(&path) {
            return Some(library);
        }
        tried.push(path);
    }
    None
}

unsafe fn try_open(path: &str) -> Option<Library> {
    let c_path = CString::new(path).ok()?;
    let handle = dlopen(c_path.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
    if handle.is_null() {
        return None;
    }
    Some(Library {
        handle,
        path: path.to_string(),
    })
}

unsafe fn resolve(handles: &[*mut c_void], name: &str) -> Result<*mut c_void, String> {
    debug_assert!(name.ends_with('\0'), "symbol names must be NUL-terminated");
    for &handle in handles {
        let symbol = dlsym(handle, name.as_ptr() as *const c_char);
        if !symbol.is_null() {
            return Ok(symbol);
        }
    }
    let name = name.trim_end_matches('\0');
    Err(format!(
        "OpenSSL symbol {name} is missing. This program needs OpenSSL 3.x; \
         the 1.1 series does not export it."
    ))
}

unsafe fn last_dl_error() -> String {
    let message = dlerror();
    if message.is_null() {
        return "none reported".to_string();
    }
    CStr::from_ptr(message).to_string_lossy().into_owned()
}

fn not_found(what: &str, tried: &[String], dl_error: String) -> String {
    // Only the distinct names are worth showing; the directory sweep makes the
    // full list long and repetitive.
    let shown: Vec<&str> = tried.iter().take(6).map(String::as_str).collect();
    format!(
        "could not load {what}. Tried {}{} (last loader error: {dl_error}). \
         Only the runtime library is needed, not a -dev package. If it is \
         installed somewhere unusual, set {LIB_DIR_VAR} to its directory, or \
         {LIBCRYPTO_VAR}/{LIBSSL_VAR} to the exact files.",
        shown.join(", "),
        if tried.len() > shown.len() {
            format!(" and {} more", tried.len() - shown.len())
        } else {
            String::new()
        }
    )
}

pub const POLLIN: c_short = 0x001;
pub const POLLOUT: c_short = 0x004;
pub const POLLERR: c_short = 0x008;
pub const POLLHUP: c_short = 0x010;
pub const POLLNVAL: c_short = 0x020;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: c_int,
    pub events: c_short,
    pub revents: c_short,
}

extern "C" {
    /// From libc, which Rust's std already links.
    pub fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
}

/// Drain OpenSSL's error queue into a human-readable string.
pub fn openssl_errors() -> String {
    let mut out = String::new();
    loop {
        let code = unsafe { ERR_get_error() };
        if code == 0 {
            break;
        }
        // c_char is signed on x86-64 and unsigned on aarch64; go through it.
        let mut buf = [0 as c_char; 256];
        unsafe { ERR_error_string_n(code, buf.as_mut_ptr(), buf.len()) };
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&b| b != 0)
            // No-op where c_char is already unsigned; needed where it is not.
            .map(|&b| {
                #[allow(clippy::unnecessary_cast)]
                {
                    b as u8
                }
            })
            .collect();
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(&String::from_utf8_lossy(&bytes));
    }
    if out.is_empty() {
        out.push_str("no OpenSSL error information");
    }
    out
}

/// An OpenSSL call that reports failure, turned into an `io::Error`.
pub fn openssl_err(what: &str) -> std::io::Error {
    std::io::Error::other(format!("{what}: {}", openssl_errors()))
}

/// Compare two byte slices without an early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bare file names must be tried before the hard-coded directories,
    /// so that the dynamic loader's own search path wins on a normal system.
    #[test]
    fn candidate_order_prefers_the_loader_then_known_directories() {
        let list = candidates(LIBCRYPTO_NAMES);
        assert_eq!(&list[..3], LIBCRYPTO_NAMES);
        assert!(list.iter().any(|c| c == "/usr/lib/libcrypto.so.3"));
        assert!(list.iter().any(|c| c == "/usr/lib64/libcrypto.so.3"));
        // Every known directory is paired with every candidate name.
        assert_eq!(list.len(), LIBCRYPTO_NAMES.len() * (SEARCH_DIRS.len() + 1));
        // OpenSSL 3's soname is preferred over the unversioned symlink.
        let three = list.iter().position(|c| c == "libcrypto.so.3").unwrap();
        let plain = list.iter().position(|c| c == "libcrypto.so").unwrap();
        let one_one = list.iter().position(|c| c == "libcrypto.so.1.1").unwrap();
        assert!(three < plain && plain < one_one);
    }

    /// The failure path: nothing opens, every attempt is recorded, and the
    /// message names the knobs that exist.
    #[test]
    fn reports_every_attempt_when_nothing_loads() {
        let mut tried = Vec::new();
        let missing = ["libnot-a-real-library-xyz.so.9"];
        let result = unsafe { open_library("TOR_UNSET_FOR_TEST", &missing, &mut tried) };
        assert!(result.is_none());
        assert_eq!(tried.len(), SEARCH_DIRS.len() + 1);
        assert!(tried.contains(&"libnot-a-real-library-xyz.so.9".to_string()));

        let message = not_found("libcrypto", &tried, "no such file".into());
        assert!(message.contains("could not load libcrypto"), "{message}");
        assert!(
            message.contains("libnot-a-real-library-xyz.so.9"),
            "{message}"
        );
        assert!(message.contains(LIB_DIR_VAR), "{message}");
        assert!(message.contains(LIBCRYPTO_VAR), "{message}");
        assert!(message.contains("not a -dev package"), "{message}");
        // The full sweep is long, so the list is abridged.
        assert!(message.contains("more"), "{message}");
    }

    /// An explicit override that cannot be loaded must warn and then fall back,
    /// not abort: the setting may be stale rather than wrong on purpose.
    #[test]
    fn explicit_override_falls_back_when_unusable() {
        // Safety: no other test reads this variable.
        unsafe { std::env::set_var("TOR_TEST_LIBCRYPTO", "/nonexistent/libcrypto.so.3") };
        let mut tried = Vec::new();
        let library = unsafe { open_library("TOR_TEST_LIBCRYPTO", LIBCRYPTO_NAMES, &mut tried) };
        unsafe { std::env::remove_var("TOR_TEST_LIBCRYPTO") };
        let library = library.expect("should fall back to the system libcrypto");
        assert!(tried.contains(&"/nonexistent/libcrypto.so.3".to_string()));
        assert!(library.path.contains("libcrypto"));
    }

    /// The whole point of the exercise: real symbols resolve, and they work.
    #[test]
    fn resolves_and_calls_a_real_symbol() {
        ensure_loaded().expect("OpenSSL should load on the build machine");
        let (ssl, crypto) = library_paths().unwrap();
        assert!(ssl.contains("libssl"), "{ssl}");
        assert!(crypto.contains("libcrypto"), "{crypto}");
        assert_eq!(
            hash::sha256(b"abc").to_vec(),
            crate::util::hex_decode(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            )
            .unwrap()
        );
    }
}
