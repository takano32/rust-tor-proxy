//! One call into the allocator, to stop it spreading across arenas.
//!
//! glibc gives each thread that contends for the heap an arena of its own, up
//! to eight per core -- sixty-four on an eight-core machine. Each arena keeps
//! its own free lists and hands very little back to the kernel, so a program
//! whose threads come and go ends up holding far more resident memory than it
//! is using. Here that showed as a peak of 55MB after one onion service visit
//! against 32MB with the arenas capped, on a program whose live data is a few
//! megabytes.
//!
//! This is worth a call because the whole point of the project is to run in
//! 128-240MB, and because the work is I/O-bound: the threads spend their time
//! waiting on sockets, not competing for the allocator, so sharing two arenas
//! costs nothing measurable.
//!
//! `mallopt` is glibc's, not POSIX's. It is looked up at run time rather than
//! linked, so a musl build simply does not find it and carries on -- musl's
//! allocator does not have this behaviour to begin with.

use std::ffi::{c_char, c_int, c_void};

/// `M_ARENA_MAX` from glibc's `malloc.h`.
const M_ARENA_MAX: c_int = -8;

/// How many arenas to allow.
const ARENA_MAX: c_int = 2;

extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Cap the allocator's arena count. Call once, before any thread is started:
/// `mallopt` only governs arenas created after it.
pub fn limit_arenas() {
    // Safety: RTLD_DEFAULT is a null handle on glibc, which searches the
    // process's own symbols. A miss returns null and is handled.
    let symbol = unsafe { dlsym(std::ptr::null_mut(), c"mallopt".as_ptr()) };
    if symbol.is_null() {
        crate::debug!("no mallopt in this libc; leaving the allocator alone");
        return;
    }
    // Safety: the signature is glibc's `int mallopt(int, int)`, which has not
    // changed since it was introduced.
    let mallopt = unsafe {
        std::mem::transmute::<*mut c_void, unsafe extern "C" fn(c_int, c_int) -> c_int>(symbol)
    };
    let ok = unsafe { mallopt(M_ARENA_MAX, ARENA_MAX) };
    if ok == 1 {
        crate::debug!("allocator limited to {ARENA_MAX} arenas");
    } else {
        crate::debug!("mallopt refused M_ARENA_MAX; leaving the allocator alone");
    }
}
