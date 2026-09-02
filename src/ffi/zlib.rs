//! Optional run-time binding to zlib, for compressed directory fetches.
//!
//! A directory document is highly compressible -- a consensus arrives at about
//! a fifth of its size -- and every relay offers `deflate`. But compression is
//! a bandwidth optimisation, not a protocol requirement: a client that cannot
//! decompress simply asks for the uncompressed document instead. So unlike
//! OpenSSL, which the client cannot work without, zlib is *optional*. Nothing
//! here panics or aborts when the library is missing; `available()` reports it
//! and the caller falls back.
//!
//! The loading strategy is the one in the parent module: `TOR_LIBZ` for an
//! explicit path, then the bare file names so that the dynamic loader does its
//! own search, then the usual library directories for images with no
//! `ld.so.cache`. The `dlopen`/`dlsym` declarations are repeated here rather
//! than shared so that this file stays self-contained and a zlib that will not
//! load can never take OpenSSL down with it.
//!
//! Only inflation is bound. The client never compresses anything.

use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use std::ffi::{CStr, CString};
use std::io;
use std::sync::OnceLock;

// From libdl, which is part of libc on glibc 2.34+ and on musl, and which
// Rust's std already links on every Linux target.
extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Same values on glibc and musl.
const RTLD_NOW: c_int = 2;
const RTLD_GLOBAL: c_int = 0x100;

const LIBZ_VAR: &str = "TOR_LIBZ";

/// The soname first; the unversioned name only exists where a `-dev` package
/// is installed, so it is a fallback rather than the first choice.
const LIBZ_NAMES: &[&str] = &["libz.so.1", "libz.so"];

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

// Return codes from zlib.h. They are not part of this module's interface: a
// caller outside it sees an io::Error, never a number.
const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_NEED_DICT: c_int = 2;
const Z_DATA_ERROR: c_int = -3;
const Z_MEM_ERROR: c_int = -4;
const Z_BUF_ERROR: c_int = -5;
const Z_VERSION_ERROR: c_int = -6;
const Z_NO_FLUSH: c_int = 0;

/// 15 (the largest window zlib supports) + 32 (work the framing out from the
/// first bytes). Relays label the encoding in the HTTP response, but a cache
/// may hand back gzip where deflate was asked for; letting zlib decide costs
/// nothing and removes the question.
const WINDOW_BITS_AUTO: c_int = 47;

/// The output buffer starts here and doubles from there. A directory document
/// expands by roughly five times, so a fetch settles after two or three
/// growths, and a small answer never allocates more than this.
const INITIAL_OUT: usize = 32 * 1024;

/// `z_stream` from zlib.h, in declaration order.
///
/// zlib takes the caller's `sizeof(z_stream)` and refuses to initialise if it
/// disagrees with its own, which is what makes it defensible to describe an
/// otherwise unversioned C struct by hand: a layout mistake becomes
/// `Z_VERSION_ERROR` at init rather than memory corruption later. The
/// allocator hooks are left null so that zlib uses its own; it fills them in
/// during initialisation.
#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: c_uint,
    total_in: c_ulong,
    next_out: *mut u8,
    avail_out: c_uint,
    total_out: c_ulong,
    msg: *const c_char,
    state: *mut c_void,
    zalloc: *const c_void,
    zfree: *const c_void,
    opaque: *mut c_void,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

impl ZStream {
    fn zeroed() -> Self {
        Self {
            next_in: std::ptr::null(),
            avail_in: 0,
            total_in: 0,
            next_out: std::ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: std::ptr::null(),
            state: std::ptr::null_mut(),
            zalloc: std::ptr::null(),
            zfree: std::ptr::null(),
            opaque: std::ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        }
    }
}

/// The four entry points, resolved once.
///
/// Function pointers and a `&'static CStr` are both `Send + Sync`, which is
/// what lets the whole thing live in a `OnceLock`. The library is never
/// `dlclose`d, so the version string it points at stays mapped for the life of
/// the process.
struct Symbols {
    inflate_init2: unsafe extern "C" fn(*mut ZStream, c_int, *const c_char, c_int) -> c_int,
    inflate: unsafe extern "C" fn(*mut ZStream, c_int) -> c_int,
    inflate_end: unsafe extern "C" fn(*mut ZStream) -> c_int,
    version: &'static CStr,
}

static LIBZ: OnceLock<Result<Symbols, String>> = OnceLock::new();

fn loaded() -> &'static Result<Symbols, String> {
    LIBZ.get_or_init(|| unsafe { load() })
}

/// Whether compressed fetches are possible at all. The library is loaded at
/// most once, on the first call.
pub fn available() -> bool {
    loaded().is_ok()
}

/// zlib's own version string, for the start-up log.
pub fn version() -> Option<&'static str> {
    loaded().as_ref().ok().and_then(|s| s.version.to_str().ok())
}

/// Inflate a zlib- or gzip-framed stream, refusing to produce more than
/// `max_out` bytes.
///
/// Several members may be concatenated: dir-spec requires that compressed
/// concatenated documents and concatenated compressed documents be treated as
/// equivalent, so a `Z_STREAM_END` that leaves input behind starts a new
/// member, appending to the same output. Whitespace between members and after
/// the last one is ignored; anything else has to inflate.
///
/// `max_out` is the compression-bomb guard, and it applies to the whole
/// concatenation rather than to one member. Exceeding it is an `InvalidData`
/// error, as is a truncated or corrupt stream. A missing zlib is reported
/// here as well, though a caller that means to fall back should ask
/// `available()` first.
pub fn inflate_all(data: &[u8], max_out: usize) -> io::Result<Vec<u8>> {
    let syms = match loaded() {
        Ok(syms) => syms,
        Err(e) => return Err(io::Error::other(format!("zlib is unavailable: {e}"))),
    };
    let mut inflater = Inflater::new(syms)?;

    // One byte of headroom above the limit. Without it, a stream that expands
    // to exactly `max_out` could not be told from one that wants to continue,
    // because both leave the buffer full.
    let cap = max_out.saturating_add(1);
    let mut out: Vec<u8> = Vec::new();
    let mut filled = 0usize;
    let mut consumed = 0usize;

    loop {
        if filled == out.len() {
            let want = out.len().saturating_mul(2).max(INITIAL_OUT).min(cap);
            // Guaranteed by the `filled > max_out` check below, which fires
            // before the buffer can reach `cap` with nothing left to fill.
            debug_assert!(want > out.len());
            out.resize(want, 0);
        }
        // avail_in and avail_out are 32-bit; a slice may in principle be
        // longer, in which case the rest is handed over on a later pass.
        let in_len = (data.len() - consumed).min(c_uint::MAX as usize);
        let out_len = (out.len() - filled).min(c_uint::MAX as usize);
        let (was_consumed, was_filled) = (consumed, filled);

        // Safety: both pointers are derived from live buffers and are paired
        // with the number of bytes actually there, `out` is borrowed uniquely,
        // and the stream is one this function initialised and has not shared.
        // zlib reads only within avail_in and writes only within avail_out,
        // and reports what it left over, which is what advances the cursors.
        let rc = unsafe {
            let strm = &mut *inflater.strm;
            strm.next_in = data.as_ptr().add(consumed);
            strm.avail_in = in_len as c_uint;
            strm.next_out = out.as_mut_ptr().add(filled);
            strm.avail_out = out_len as c_uint;
            let rc = (syms.inflate)(strm, Z_NO_FLUSH);
            consumed += in_len - strm.avail_in as usize;
            filled += out_len - strm.avail_out as usize;
            rc
        };

        if filled > max_out {
            return Err(crate::util::invalid_data(format!(
                "compressed data expands past the {max_out}-byte limit"
            )));
        }
        match rc {
            Z_STREAM_END | Z_OK | Z_BUF_ERROR => {
                // Z_BUF_ERROR is not a failure here: it means no progress was
                // possible, which is the ordinary report when the output
                // buffer filled up, and the next pass supplies a bigger one.
                // Since avail_out is never zero on entry, a pass that neither
                // consumed nor produced anything can only mean the input ran
                // out mid-stream. Rejecting it also makes the loop terminate.
                if consumed == was_consumed && filled == was_filled {
                    return Err(crate::util::invalid_data(
                        "compressed data ends in the middle of a stream",
                    ));
                }
                if rc == Z_STREAM_END {
                    // Step over padding rather than testing whether all of the
                    // rest is padding: a response made of thousands of tiny
                    // members would otherwise rescan its own tail once per
                    // member. Advancing `consumed` keeps the whole loop linear.
                    while consumed < data.len() && is_padding(data[consumed]) {
                        consumed += 1;
                    }
                    if consumed == data.len() {
                        break;
                    }
                    inflater.restart()?;
                }
            }
            Z_DATA_ERROR => {
                return Err(crate::util::invalid_data(format!(
                    "not a valid zlib or gzip stream: {}",
                    inflater.message()
                )))
            }
            Z_NEED_DICT => {
                return Err(crate::util::invalid_data(
                    "compressed data wants a preset dictionary, which no \
                     directory document uses",
                ))
            }
            Z_MEM_ERROR => return Err(io::Error::other("zlib ran out of memory")),
            _ => return Err(io::Error::other(format!("inflate failed ({rc})"))),
        }
    }

    out.truncate(filled);
    Ok(out)
}

/// What may sit between or after members without being a member itself. A
/// cache occasionally appends a newline; nothing else is tolerated, since real
/// trailing bytes would be a document we had quietly failed to read.
fn is_padding(b: u8) -> bool {
    b.is_ascii_whitespace() || b == 0
}

/// An initialised inflate state, ended in `Drop`.
///
/// The point of the type is that `inflateEnd` cannot be skipped: every exit
/// from `inflate_all`, including the early returns for a corrupt stream and
/// for an over-long one, runs it.
struct Inflater {
    /// Boxed because zlib's inflate state keeps a back-pointer to the
    /// `z_stream` it was initialised with and compares it on every call
    /// (`inflateStateCheck`). The struct must therefore not move afterwards,
    /// and a box keeps its address fixed even as the guard itself is returned
    /// out of the constructor and moved about.
    strm: Box<ZStream>,
    syms: &'static Symbols,
}

impl Inflater {
    fn new(syms: &'static Symbols) -> io::Result<Self> {
        let mut strm = Box::new(ZStream::zeroed());
        init(syms, &mut strm)?;
        Ok(Self { strm, syms })
    }

    /// Finish the current member and begin a new one in the same box, for the
    /// concatenated case. zlib has `inflateReset2` for exactly this, but it is
    /// a fifth symbol to resolve and end-then-init is just as effective.
    fn restart(&mut self) -> io::Result<()> {
        // Safety: the state was initialised by `init` and is not shared. It is
        // null afterwards, which is why `init` failing below leaves the
        // destructor with nothing to do rather than a double free.
        unsafe { (self.syms.inflate_end)(&mut *self.strm) };
        init(self.syms, &mut self.strm)
    }

    /// zlib's own description of the last failure, if it left one.
    fn message(&self) -> String {
        if self.strm.msg.is_null() {
            return "no detail".to_string();
        }
        // Safety: a non-null `msg` is a static string inside libz, valid for
        // as long as the library stays mapped, which is for ever.
        unsafe { CStr::from_ptr(self.strm.msg) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Inflater {
    fn drop(&mut self) {
        // Safety: the stream belongs to this value alone and is either
        // initialised or already ended; zlib detects the latter and returns
        // Z_STREAM_ERROR without touching anything, so this cannot double-free.
        unsafe { (self.syms.inflate_end)(&mut *self.strm) };
    }
}

fn init(syms: &Symbols, strm: &mut ZStream) -> io::Result<()> {
    let size = std::mem::size_of::<ZStream>() as c_int;
    // Safety: `strm` is a live, uniquely borrowed stream, and the version
    // string and size are the ones zlib compares against before it touches
    // anything. When it declines it leaves nothing allocated, so no cleanup is
    // owed on the error path.
    let rc = unsafe { (syms.inflate_init2)(strm, WINDOW_BITS_AUTO, syms.version.as_ptr(), size) };
    match rc {
        Z_OK => Ok(()),
        Z_VERSION_ERROR => Err(io::Error::other(format!(
            "zlib {} rejected our declaration of z_stream ({size} bytes)",
            syms.version.to_string_lossy()
        ))),
        _ => Err(io::Error::other(format!("inflateInit2_ failed ({rc})"))),
    }
}

unsafe fn load() -> Result<Symbols, String> {
    let mut tried = Vec::new();
    let handle = match open_library(&mut tried) {
        Some(handle) => handle,
        None => {
            return Err(format!(
                "no zlib among {}; set {LIBZ_VAR} to its path if it lives \
                 somewhere unusual",
                tried.join(", ")
            ))
        }
    };
    // The version has to be read before anything else: inflateInit2_ wants it
    // as an argument, and a library that has the name but not the symbols is
    // better rejected here than at the first fetch.
    let zlib_version = std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> *const c_char>(
        resolve(handle, "zlibVersion\0")?,
    );
    let version_ptr = zlib_version();
    if version_ptr.is_null() {
        return Err("zlibVersion() returned nothing".to_string());
    }
    Ok(Symbols {
        inflate_init2: std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*mut ZStream, c_int, *const c_char, c_int) -> c_int,
        >(resolve(handle, "inflateInit2_\0")?),
        inflate: std::mem::transmute::<
            *mut c_void,
            unsafe extern "C" fn(*mut ZStream, c_int) -> c_int,
        >(resolve(handle, "inflate\0")?),
        inflate_end: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut ZStream) -> c_int>(
            resolve(handle, "inflateEnd\0")?,
        ),
        // Compiled into libz, and so outlives every use of it here.
        version: CStr::from_ptr(version_ptr),
    })
}

unsafe fn open_library(tried: &mut Vec<String>) -> Option<*mut c_void> {
    if let Some(path) = std::env::var(LIBZ_VAR).ok().filter(|p| !p.is_empty()) {
        match try_open(&path) {
            Some(handle) => return Some(handle),
            None => {
                // The setting may be left over from another machine, so fall
                // back rather than give up -- but never in silence.
                crate::warn!("{LIBZ_VAR} is set to {path}, which could not be loaded");
                tried.push(path);
            }
        }
    }
    for path in candidates() {
        if let Some(handle) = try_open(&path) {
            return Some(handle);
        }
        tried.push(path);
    }
    None
}

/// Where to look, in order of preference: the bare names first, so that the
/// dynamic loader's own search path wins on a normal system.
fn candidates() -> Vec<String> {
    let mut out = Vec::with_capacity(LIBZ_NAMES.len() * (SEARCH_DIRS.len() + 1));
    out.extend(LIBZ_NAMES.iter().map(|name| (*name).to_string()));
    for dir in SEARCH_DIRS {
        out.extend(LIBZ_NAMES.iter().map(|name| format!("{dir}/{name}")));
    }
    out
}

unsafe fn try_open(path: &str) -> Option<*mut c_void> {
    let c_path = CString::new(path).ok()?;
    let handle = dlopen(c_path.as_ptr(), RTLD_NOW | RTLD_GLOBAL);
    if handle.is_null() {
        None
    } else {
        Some(handle)
    }
}

unsafe fn resolve(handle: *mut c_void, name: &str) -> Result<*mut c_void, String> {
    debug_assert!(name.ends_with('\0'), "symbol names must be NUL-terminated");
    let symbol = dlsym(handle, name.as_ptr() as *const c_char);
    if symbol.is_null() {
        return Err(format!(
            "the library found has no {}, so it is not zlib",
            name.trim_end_matches('\0')
        ));
    }
    Ok(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory-document-shaped string with zlib framing. Hard-coded so
    /// that the test depends on nothing but libz itself.
    const ZLIB_FOX: &[u8] = &[
        0x78, 0xda, 0x73, 0x48, 0xc9, 0x2c, 0x4a, 0x4d, 0x2e, 0xc9, 0x2f, 0xaa, 0xd4, 0x2d, 0xce,
        0x4c, 0xcf, 0x4b, 0x2c, 0x29, 0x2d, 0x4a, 0x55, 0x28, 0xce, 0x48, 0x34, 0x32, 0x35, 0x53,
        0xa8, 0x20, 0x12, 0x70, 0x85, 0x64, 0xa4, 0x2a, 0x14, 0x96, 0x66, 0x26, 0x67, 0x2b, 0x24,
        0x15, 0xe5, 0x97, 0xe7, 0x29, 0xa4, 0xe5, 0x57, 0x28, 0x64, 0x95, 0xe6, 0x16, 0x14, 0x2b,
        0xe4, 0x97, 0xa5, 0x16, 0x29, 0x94, 0x00, 0xa5, 0x73, 0x12, 0xab, 0x2a, 0x15, 0x52, 0xf2,
        0xd3, 0xf5, 0x46, 0x15, 0x93, 0xaf, 0x18, 0x00, 0x88, 0xb0, 0x9d, 0x80,
    ];

    /// The same bytes with gzip framing, which windowBits 47 has to recognise
    /// on its own.
    const GZIP_FOX: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x73, 0x48, 0xc9, 0x2c, 0x4a,
        0x4d, 0x2e, 0xc9, 0x2f, 0xaa, 0xd4, 0x2d, 0xce, 0x4c, 0xcf, 0x4b, 0x2c, 0x29, 0x2d, 0x4a,
        0x55, 0x28, 0xce, 0x48, 0x34, 0x32, 0x35, 0x53, 0xa8, 0x20, 0x12, 0x70, 0x85, 0x64, 0xa4,
        0x2a, 0x14, 0x96, 0x66, 0x26, 0x67, 0x2b, 0x24, 0x15, 0xe5, 0x97, 0xe7, 0x29, 0xa4, 0xe5,
        0x57, 0x28, 0x64, 0x95, 0xe6, 0x16, 0x14, 0x2b, 0xe4, 0x97, 0xa5, 0x16, 0x29, 0x94, 0x00,
        0xa5, 0x73, 0x12, 0xab, 0x2a, 0x15, 0x52, 0xf2, 0xd3, 0xf5, 0x46, 0x15, 0x93, 0xaf, 0x18,
        0x00, 0xeb, 0xb2, 0x6a, 0x32, 0xad, 0x01, 0x00, 0x00,
    ];

    /// 100,000 bytes of `A` in 121 bytes: an 826-fold expansion, which is what
    /// the `max_out` guard exists for.
    const ZLIB_BOMB: &[u8] = &[
        0x78, 0xda, 0xed, 0xc1, 0x31, 0x01, 0x00, 0x00, 0x00, 0xc2, 0xa0, 0x6c, 0xeb, 0x5f, 0xca,
        0x1a, 0x1e, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaf, 0x06, 0xe2, 0x0c, 0x34,
        0x6e,
    ];

    /// `first document\n` with zlib framing followed by `second document\n`
    /// with gzip framing: two documents compressed separately and then
    /// concatenated, which dir-spec says must read the same as one compressed
    /// document containing both.
    const CONCATENATED: &[u8] = &[
        0x78, 0xda, 0x4b, 0xcb, 0x2c, 0x2a, 0x2e, 0x51, 0x48, 0xc9, 0x4f, 0x2e, 0xcd, 0x4d, 0xcd,
        0x2b, 0xe1, 0x02, 0x00, 0x2f, 0x91, 0x05, 0xb2, 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0xff, 0x2b, 0x4e, 0x4d, 0xce, 0xcf, 0x4b, 0x51, 0x48, 0xc9, 0x4f, 0x2e, 0xcd,
        0x4d, 0xcd, 0x2b, 0xe1, 0x02, 0x00, 0x8d, 0xe4, 0xc0, 0xb1, 0x10, 0x00, 0x00, 0x00,
    ];

    /// The 429 bytes that ZLIB_FOX and GZIP_FOX both encode.
    fn fox() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"@directory-signature sha256 ");
        out.extend(std::iter::repeat_n(b'x', 40));
        out.push(b'\n');
        for _ in 0..8 {
            out.extend_from_slice(b"The quick brown fox jumps over the lazy dog.\n");
        }
        out
    }

    /// zlib is optional, so a machine without it must not fail the suite.
    fn missing() -> bool {
        if available() {
            return false;
        }
        eprintln!("no zlib on this machine; skipping");
        true
    }

    /// zlib compares our `sizeof(z_stream)` with its own and refuses to
    /// initialise if they differ, so a wrong layout would surface as a
    /// mysterious Z_VERSION_ERROR at the first fetch. Pin it here instead.
    #[test]
    fn zstream_matches_the_c_declaration() {
        assert_eq!(std::mem::size_of::<ZStream>(), 112);
        assert_eq!(std::mem::align_of::<ZStream>(), 8);
        // Order matters as much as size: these are the fields inflate() reads
        // back, and transposing them would leave the size unchanged.
        assert_eq!(std::mem::offset_of!(ZStream, avail_in), 8);
        assert_eq!(std::mem::offset_of!(ZStream, avail_out), 32);
    }

    #[test]
    fn version_is_reported_when_the_library_is_there() {
        if missing() {
            return;
        }
        let version = version().expect("a loaded zlib has a version");
        assert!(
            version.starts_with('1') || version.starts_with('2'),
            "{version}"
        );
    }

    #[test]
    fn round_trip_of_a_zlib_stream() {
        if missing() {
            return;
        }
        assert_eq!(inflate_all(ZLIB_FOX, 1 << 20).unwrap(), fox());
        // Padding after the end is what a cache may add; not an error.
        let mut padded = ZLIB_FOX.to_vec();
        padded.extend_from_slice(b"\n\n");
        assert_eq!(inflate_all(&padded, 1 << 20).unwrap(), fox());
    }

    /// windowBits 47 has to detect gzip framing without being told.
    #[test]
    fn round_trip_of_a_gzip_stream() {
        if missing() {
            return;
        }
        assert_eq!(inflate_all(GZIP_FOX, 1 << 20).unwrap(), fox());
    }

    /// dir-spec: concatenated compressed documents and compressed concatenated
    /// documents are equivalent, so the second member must not be dropped.
    #[test]
    fn concatenated_members_are_all_inflated() {
        if missing() {
            return;
        }
        assert_eq!(
            inflate_all(CONCATENATED, 1 << 20).unwrap(),
            b"first document\nsecond document\n".to_vec()
        );
        // Two long members, so that the second one also crosses a growth of
        // the output buffer rather than fitting in whatever was left.
        let mut twice = ZLIB_FOX.to_vec();
        twice.extend_from_slice(GZIP_FOX);
        let mut both = fox();
        both.extend_from_slice(&fox());
        assert_eq!(inflate_all(&twice, 1 << 20).unwrap(), both);

        // Many members, separated by the newline a cache may insert: the
        // padding has to be stepped over rather than ending the document.
        let mut many = Vec::new();
        let mut expected = Vec::new();
        for _ in 0..64 {
            many.extend_from_slice(ZLIB_FOX);
            many.push(b'\n');
            expected.extend_from_slice(&fox());
        }
        assert_eq!(inflate_all(&many, 1 << 20).unwrap(), expected);
    }

    #[test]
    fn a_truncated_stream_is_an_error() {
        if missing() {
            return;
        }
        for cut in [1, 2, 5, ZLIB_FOX.len() - 1] {
            let e = inflate_all(&ZLIB_FOX[..cut], 1 << 20).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "cut at {cut}: {e}");
        }
        assert!(inflate_all(b"", 1 << 20).is_err());
        // Trailing bytes that are neither padding nor a stream are an error
        // too: they would be a document we had quietly failed to read.
        let mut trailing = ZLIB_FOX.to_vec();
        trailing.extend_from_slice(b"not compressed at all");
        assert!(inflate_all(&trailing, 1 << 20).is_err());
    }

    #[test]
    fn corrupt_input_is_an_error_not_a_panic() {
        if missing() {
            return;
        }
        let mut damaged = ZLIB_FOX.to_vec();
        damaged[10] ^= 0xff;
        let e = inflate_all(&damaged, 1 << 20).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        assert!(inflate_all(b"this is plain text", 1 << 20).is_err());
    }

    #[test]
    fn max_out_stops_a_compression_bomb() {
        if missing() {
            return;
        }
        // Exactly at the limit is allowed; a byte less is not.
        assert_eq!(inflate_all(ZLIB_BOMB, 100_000).unwrap().len(), 100_000);
        for limit in [0, 1, 4096, 99_999] {
            let e = inflate_all(ZLIB_BOMB, limit).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "limit {limit}: {e}");
            assert!(e.to_string().contains("limit"), "{e}");
        }
        // The cap covers the concatenation as a whole, not each member: the
        // first member alone is 15 bytes and fits, both together do not.
        assert!(inflate_all(CONCATENATED, 20).is_err());
        assert_eq!(inflate_all(CONCATENATED, 31).unwrap().len(), 31);
    }

    /// The bare names have to come before the hard-coded directories, so that
    /// the dynamic loader's own search path wins on a normal system.
    #[test]
    fn candidate_order_prefers_the_loader() {
        let list = candidates();
        assert_eq!(&list[..2], LIBZ_NAMES);
        assert!(list.iter().any(|c| c == "/usr/lib/libz.so.1"));
        assert_eq!(list.len(), LIBZ_NAMES.len() * (SEARCH_DIRS.len() + 1));
    }
}
