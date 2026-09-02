//! Hand-written FFI to the system OpenSSL 3 (`libssl.so.3` / `libcrypto.so.3`).
//!
//! Only the handful of primitives the Tor protocol needs is bound here. Opaque
//! OpenSSL types are all declared as `*mut c_void`; the safe wrappers in the
//! submodules own them and free them in `Drop`, and never hand a raw pointer
//! out. OpenSSL 3 self-initialises on first use, so there is no init call.
//!
//! `OPENSSL_free` and `SSL_set_tlsext_host_name` are macros rather than
//! exported symbols, so they are deliberately not used: buffers are sized with
//! a first `i2d_X509(x, NULL)` call, and no SNI is sent (Tor relays do not want
//! one anyway).

#![allow(non_snake_case)]

use std::ffi::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_void};

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

#[link(name = "ssl")]
extern "C" {
    pub fn TLS_client_method() -> *const c_void;
    pub fn SSL_CTX_new(method: *const c_void) -> *mut c_void;
    pub fn SSL_CTX_free(ctx: *mut c_void);
    pub fn SSL_CTX_ctrl(ctx: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_set_verify(ctx: *mut c_void, mode: c_int, callback: *const c_void);
    pub fn SSL_CTX_set_security_level(ctx: *mut c_void, level: c_int);
    pub fn SSL_new(ctx: *mut c_void) -> *mut c_void;
    pub fn SSL_free(ssl: *mut c_void);
    pub fn SSL_set_fd(ssl: *mut c_void, fd: c_int) -> c_int;
    pub fn SSL_connect(ssl: *mut c_void) -> c_int;
    pub fn SSL_read(ssl: *mut c_void, buf: *mut c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *mut c_void, buf: *const c_void, num: c_int) -> c_int;
    pub fn SSL_get_error(ssl: *const c_void, ret: c_int) -> c_int;
    pub fn SSL_shutdown(ssl: *mut c_void) -> c_int;
    pub fn SSL_get1_peer_certificate(ssl: *const c_void) -> *mut c_void;
}

#[link(name = "crypto")]
extern "C" {
    pub fn X509_free(x: *mut c_void);
    pub fn i2d_X509(x: *const c_void, out: *mut *mut c_uchar) -> c_int;

    pub fn EVP_sha1() -> *const c_void;
    pub fn EVP_sha256() -> *const c_void;
    pub fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut c_uchar,
        size: *mut c_uint,
        md_type: *const c_void,
        engine: *mut c_void,
    ) -> c_int;
    pub fn EVP_MD_CTX_new() -> *mut c_void;
    pub fn EVP_MD_CTX_free(ctx: *mut c_void);
    pub fn EVP_DigestInit_ex(
        ctx: *mut c_void,
        md_type: *const c_void,
        engine: *mut c_void,
    ) -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut c_void, data: *const c_void, count: usize) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut c_void, md: *mut c_uchar, size: *mut c_uint) -> c_int;
    pub fn EVP_MD_CTX_copy_ex(out: *mut c_void, inp: *const c_void) -> c_int;

    pub fn HMAC(
        md: *const c_void,
        key: *const c_void,
        key_len: c_int,
        data: *const c_uchar,
        data_len: usize,
        out: *mut c_uchar,
        out_len: *mut c_uint,
    ) -> *mut c_uchar;

    pub fn EVP_aes_128_ctr() -> *const c_void;
    pub fn EVP_CIPHER_CTX_new() -> *mut c_void;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut c_void);
    pub fn EVP_EncryptInit_ex(
        ctx: *mut c_void,
        cipher: *const c_void,
        engine: *mut c_void,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    pub fn EVP_EncryptUpdate(
        ctx: *mut c_void,
        out: *mut c_uchar,
        out_len: *mut c_int,
        inp: *const c_uchar,
        in_len: c_int,
    ) -> c_int;

    pub fn EVP_PKEY_free(pkey: *mut c_void);
    pub fn EVP_PKEY_get_size(pkey: *const c_void) -> c_int;
    pub fn EVP_PKEY_CTX_new(pkey: *mut c_void, engine: *mut c_void) -> *mut c_void;
    pub fn EVP_PKEY_CTX_new_id(id: c_int, engine: *mut c_void) -> *mut c_void;
    pub fn EVP_PKEY_CTX_free(ctx: *mut c_void);
    pub fn EVP_PKEY_keygen_init(ctx: *mut c_void) -> c_int;
    pub fn EVP_PKEY_keygen(ctx: *mut c_void, ppkey: *mut *mut c_void) -> c_int;
    pub fn EVP_PKEY_get_raw_public_key(
        pkey: *const c_void,
        out: *mut c_uchar,
        out_len: *mut usize,
    ) -> c_int;
    pub fn EVP_PKEY_new_raw_public_key(
        key_type: c_int,
        engine: *mut c_void,
        key: *const c_uchar,
        key_len: usize,
    ) -> *mut c_void;
    #[cfg(test)]
    pub fn EVP_PKEY_new_raw_private_key(
        key_type: c_int,
        engine: *mut c_void,
        key: *const c_uchar,
        key_len: usize,
    ) -> *mut c_void;
    pub fn EVP_PKEY_derive_init(ctx: *mut c_void) -> c_int;
    pub fn EVP_PKEY_derive_set_peer(ctx: *mut c_void, peer: *mut c_void) -> c_int;
    pub fn EVP_PKEY_derive(ctx: *mut c_void, key: *mut c_uchar, key_len: *mut usize) -> c_int;

    pub fn EVP_DigestVerifyInit(
        ctx: *mut c_void,
        pctx: *mut *mut c_void,
        md_type: *const c_void,
        engine: *mut c_void,
        pkey: *mut c_void,
    ) -> c_int;
    pub fn EVP_DigestVerify(
        ctx: *mut c_void,
        sig: *const c_uchar,
        sig_len: usize,
        tbs: *const c_uchar,
        tbs_len: usize,
    ) -> c_int;

    pub fn d2i_PublicKey(
        key_type: c_int,
        a: *mut *mut c_void,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut c_void;
    pub fn EVP_PKEY_verify_recover_init(ctx: *mut c_void) -> c_int;
    pub fn EVP_PKEY_verify_recover(
        ctx: *mut c_void,
        out: *mut c_uchar,
        out_len: *mut usize,
        sig: *const c_uchar,
        sig_len: usize,
    ) -> c_int;
    pub fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut c_void, padding: c_int) -> c_int;

    pub fn RAND_bytes(buf: *mut c_uchar, num: c_int) -> c_int;

    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
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
