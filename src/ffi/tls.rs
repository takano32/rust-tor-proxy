//! A TLS client stream over an owned `TcpStream`.
//!
//! Certificate verification is deliberately disabled: Tor relays present
//! self-signed link certificates, and their authenticity is established later
//! by the CERTS cell, which binds the certificate's SHA-256 to the relay's
//! Ed25519 identity. That digest is captured here right after the handshake.
//!
//! The handshake and the Tor link handshake that follows run on a blocking
//! socket with a timeout. `set_nonblocking` then hands the stream to a single
//! `poll(2)`-driven I/O thread, so the `SSL` object is never used from two
//! threads at once.

use std::ffi::{c_int, c_void};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use super::hash;
use super::*;

pub struct SslStream {
    ssl: *mut c_void,
    ctx: *mut c_void,
    /// Kept alive for as long as the `SSL` holds its file descriptor.
    sock: TcpStream,
    peer_cert_sha256: [u8; 32],
    /// Set when the last operation asked to wait for writability instead of
    /// readability (TLS renegotiation or a key update mid-read).
    want_write: bool,
}

// `ssl`/`ctx` are owned exclusively by this value and never aliased.
unsafe impl Send for SslStream {}

impl SslStream {
    pub fn connect(sock: TcpStream, timeout: Duration) -> io::Result<Self> {
        sock.set_nodelay(true)?;
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;

        let ctx = unsafe { SSL_CTX_new(TLS_client_method()) };
        if ctx.is_null() {
            return Err(openssl_err("SSL_CTX_new"));
        }
        let mut stream = Self {
            ssl: std::ptr::null_mut(),
            ctx,
            sock,
            peer_cert_sha256: [0u8; 32],
            want_write: false,
        };

        unsafe {
            SSL_CTX_set_verify(stream.ctx, SSL_VERIFY_NONE, std::ptr::null());
            // Relay link certificates are self-signed and historically small;
            // since we do not trust them anyway, do not let a distribution's
            // raised default security level reject the handshake.
            SSL_CTX_set_security_level(stream.ctx, 1);
            // Allow short writes and a moved buffer on retry, so the I/O loop
            // can make progress a chunk at a time on a non-blocking socket.
            SSL_CTX_ctrl(
                stream.ctx,
                SSL_CTRL_MODE,
                SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
                std::ptr::null_mut(),
            );
        }

        stream.ssl = unsafe { SSL_new(stream.ctx) };
        if stream.ssl.is_null() {
            return Err(openssl_err("SSL_new"));
        }
        if unsafe { SSL_set_fd(stream.ssl, stream.sock.as_raw_fd()) } != 1 {
            return Err(openssl_err("SSL_set_fd"));
        }

        let deadline = Instant::now() + timeout;
        loop {
            let rc = unsafe { SSL_connect(stream.ssl) };
            if rc == 1 {
                break;
            }
            let err = unsafe { SSL_get_error(stream.ssl, rc) };
            let retryable = err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
            if !retryable {
                return Err(openssl_err("SSL_connect"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ));
            }
        }

        stream.peer_cert_sha256 = stream.read_peer_cert_digest()?;
        Ok(stream)
    }

    /// Hand the stream over to the poll-driven I/O loop: no socket timeouts,
    /// and `WouldBlock` instead of blocking.
    pub fn set_nonblocking(&mut self) -> io::Result<()> {
        self.sock.set_read_timeout(None)?;
        self.sock.set_write_timeout(None)?;
        self.sock.set_nonblocking(true)
    }

    fn read_peer_cert_digest(&self) -> io::Result<[u8; 32]> {
        let cert = unsafe { SSL_get1_peer_certificate(self.ssl) };
        if cert.is_null() {
            return Err(openssl_err("SSL_get1_peer_certificate"));
        }
        let result = (|| {
            let len = unsafe { i2d_X509(cert, std::ptr::null_mut()) };
            if len <= 0 {
                return Err(openssl_err("i2d_X509 (length)"));
            }
            let mut der = vec![0u8; len as usize];
            let mut ptr = der.as_mut_ptr();
            let written = unsafe { i2d_X509(cert, &mut ptr) };
            if written != len {
                return Err(openssl_err("i2d_X509"));
            }
            Ok(hash::sha256(&der))
        })();
        unsafe { X509_free(cert) };
        result
    }

    /// SHA-256 of the peer's TLS certificate in DER form. The CERTS cell's
    /// CertType 5 certificate must certify exactly this value.
    pub fn peer_cert_sha256(&self) -> &[u8; 32] {
        &self.peer_cert_sha256
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// True if the last `WouldBlock` was really "wait for writability".
    pub fn wants_write(&self) -> bool {
        self.want_write
    }

    pub fn shutdown(&mut self) {
        unsafe { SSL_shutdown(self.ssl) };
        let _ = self.sock.shutdown(std::net::Shutdown::Both);
    }

    fn map_error(&mut self, rc: c_int, what: &str) -> io::Error {
        match unsafe { SSL_get_error(self.ssl, rc) } {
            SSL_ERROR_WANT_READ => {
                self.want_write = false;
                io::Error::new(io::ErrorKind::WouldBlock, "TLS wants more input")
            }
            SSL_ERROR_WANT_WRITE => {
                self.want_write = true;
                io::Error::new(io::ErrorKind::WouldBlock, "TLS wants to write")
            }
            _ => openssl_err(what),
        }
    }
}

impl Read for SslStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let cap = buf.len().min(c_int::MAX as usize) as c_int;
        let rc = unsafe { SSL_read(self.ssl, buf.as_mut_ptr() as *mut c_void, cap) };
        if rc > 0 {
            self.want_write = false;
            return Ok(rc as usize);
        }
        if unsafe { SSL_get_error(self.ssl, rc) } == SSL_ERROR_ZERO_RETURN {
            return Ok(0);
        }
        Err(self.map_error(rc, "SSL_read"))
    }
}

impl Write for SslStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let cap = buf.len().min(c_int::MAX as usize) as c_int;
        let rc = unsafe { SSL_write(self.ssl, buf.as_ptr() as *const c_void, cap) };
        if rc > 0 {
            self.want_write = false;
            return Ok(rc as usize);
        }
        Err(self.map_error(rc, "SSL_write"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for SslStream {
    fn drop(&mut self) {
        if !self.ssl.is_null() {
            unsafe { SSL_free(self.ssl) };
        }
        if !self.ctx.is_null() {
            unsafe { SSL_CTX_free(self.ctx) };
        }
    }
}
