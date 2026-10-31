//! The status page: `GET /status` on the proxy port answers with JSON.
//!
//! It is public, so it says nothing about who uses the proxy or where they
//! go: no client addresses, no destinations, no onion addresses, and no guard
//! identities (knowing a client's guards is a first step towards finding its
//! traffic). What is left is enough to tell whether the process is healthy
//! and which build it is running -- the counters below, the consensus it
//! holds, the shape of its circuit pool, and its memory use.

use std::fmt::Write as _;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::tor::client::{ClientStatus, TorClient};

/// A process-wide event count.
pub struct Counter(AtomicU64);

impl Counter {
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Connections accepted on the listening port, of any kind.
pub static ACCEPTED: Counter = Counter::new();
/// Connections that never got as far as a request: an unknown protocol, a
/// malformed or refused handshake, a plain proxied HTTP request, a timeout.
pub static HANDSHAKE_FAILED: Counter = Counter::new();
pub static STATUS_REQUESTS: Counter = Counter::new();
pub static SOCKS5: Counter = Counter::new();
pub static SOCKS4: Counter = Counter::new();
pub static HTTP_CONNECT: Counter = Counter::new();
/// Requests for a `.onion` address (a subset of the three above).
pub static ONION: Counter = Counter::new();
/// Requests whose stream opened and whose client was told so.
pub static SUCCEEDED: Counter = Counter::new();
/// Streams being relayed right now.
pub static ACTIVE: Counter = Counter::new();
/// Bytes from clients into Tor, and from Tor back to clients.
pub static BYTES_UP: Counter = Counter::new();
pub static BYTES_DOWN: Counter = Counter::new();

/// Failed requests, by the SOCKS5 reply code they were answered with.
static FAILED: [Counter; 9] = [const { Counter::new() }; 9];

/// The SOCKS5 reply codes, as the names the page reports them under.
const FAILURE_NAMES: [&str; 9] = [
    "succeeded",
    "general_failure",
    "not_allowed",
    "network_unreachable",
    "host_unreachable",
    "connection_refused",
    "ttl_expired",
    "command_not_supported",
    "address_type_not_supported",
];

pub fn failed(reply_code: u8) {
    FAILED[usize::from(reply_code).min(FAILED.len() - 1)].inc();
}

static STARTED: OnceLock<(Instant, u64)> = OnceLock::new();

/// Note the start of the process, for the uptime. Call once, early.
pub fn mark_start() {
    STARTED.get_or_init(|| (Instant::now(), now_unix()));
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The commit the binary was built from, when the build said
/// (`RUST_TOR_PROXY_COMMIT=$(git rev-parse --short HEAD) cargo build`).
/// There is no build script to find it out, by design.
const COMMIT: Option<&str> = option_env!("RUST_TOR_PROXY_COMMIT");

/// The whole page. `client` is `None` while the Tor client is bootstrapping.
pub fn render(listen_port: u16, client: Option<&TorClient>) -> String {
    let (started, started_unix) = *STARTED.get_or_init(|| (Instant::now(), now_unix()));
    let mut j = Json::default();
    j.open();
    j.str("version", env!("CARGO_PKG_VERSION"));
    match COMMIT {
        Some(commit) => j.str("commit", commit),
        None => j.null("commit"),
    }
    j.str(
        "state",
        if client.is_some() {
            "ready"
        } else {
            "bootstrapping"
        },
    );
    j.num("listen_port", listen_port.into());
    j.num("now_unix", now_unix());
    j.num("started_unix", started_unix);
    j.num("uptime_seconds", started.elapsed().as_secs());

    j.key("connections");
    j.open();
    j.num("accepted", ACCEPTED.get());
    j.num("active", ACTIVE.get());
    j.num("succeeded", SUCCEEDED.get());
    j.num("handshake_failed", HANDSHAKE_FAILED.get());
    j.num("status_requests", STATUS_REQUESTS.get());
    j.key("requests");
    j.open();
    j.num("socks5", SOCKS5.get());
    j.num("socks4", SOCKS4.get());
    j.num("http_connect", HTTP_CONNECT.get());
    j.num("onion", ONION.get());
    j.close();
    j.key("failed");
    j.open();
    for (name, count) in FAILURE_NAMES.iter().zip(&FAILED).skip(1) {
        j.num(name, count.get());
    }
    j.close();
    j.close();

    j.key("bytes");
    j.open();
    j.num("from_clients", BYTES_UP.get());
    j.num("to_clients", BYTES_DOWN.get());
    j.close();

    match client.map(TorClient::status) {
        Some(status) => tor_section(&mut j, &status),
        None => j.null("tor"),
    }

    j.key("process");
    j.open();
    let proc_status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for (field, name) in [
        ("VmRSS", "vm_rss_kb"),
        ("VmHWM", "vm_hwm_kb"),
        ("Threads", "threads"),
    ] {
        match proc_field(&proc_status, field) {
            Some(value) => j.num(name, value),
            None => j.null(name),
        }
    }
    j.close();

    j.key("runtime");
    j.open();
    j.str("arch", std::env::consts::ARCH);
    j.str("os", std::env::consts::OS);
    match crate::ffi::library_paths() {
        Some((ssl, crypto)) => {
            j.str("libssl", ssl);
            j.str("libcrypto", crypto);
        }
        None => {
            j.null("libssl");
            j.null("libcrypto");
        }
    }
    match crate::ffi::zlib::version() {
        Some(version) => j.str("zlib", version),
        None => j.null("zlib"),
    }
    j.close();

    j.close();
    j.finish()
}

fn tor_section(j: &mut Json, s: &ClientStatus) {
    let now = now_unix();
    j.key("tor");
    j.open();
    j.key("consensus");
    j.open();
    j.num("relays", s.relays as u64);
    j.num("guards", s.guard_relays as u64);
    j.num("exits", s.exit_relays as u64);
    j.str("valid_after", &crate::util::format_datetime(s.valid_after));
    j.str("fresh_until", &crate::util::format_datetime(s.fresh_until));
    j.str("valid_until", &crate::util::format_datetime(s.valid_until));
    j.num("age_seconds", now.saturating_sub(s.valid_after));
    j.bool("fresh", now < s.fresh_until);
    j.bool("live", now < s.valid_until);
    j.close();
    j.key("guards");
    j.open();
    j.num("count", s.guards as u64);
    j.num("demoted", s.guards_demoted as u64);
    j.num("unreachable", s.guards_unreachable as u64);
    j.bool("channel_open", s.guard_channel_open);
    j.num("slow_guard_changes", s.slow_guard_changes as u64);
    j.close();
    j.key("circuits");
    j.open();
    j.num("stubs", s.stubs as u64);
    j.num("exit", s.circuits as u64);
    j.num("onion", s.onion_circuits as u64);
    j.num("onion_descriptors_cached", s.descriptors as u64);
    j.bool("hsdir_ring_built", s.hsdir_ring_built);
    j.close();
    j.close();
}

/// The number at the start of a `/proc/<pid>/status` field (`VmRSS:  1234 kB`).
fn proc_field(text: &str, field: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Just enough of a JSON writer for one nested object, indented two spaces.
#[derive(Default)]
struct Json {
    out: String,
    depth: usize,
    /// Whether the object being written already has a member, per level.
    has_member: Vec<bool>,
}

impl Json {
    fn open(&mut self) {
        self.out.push('{');
        self.depth += 1;
        self.has_member.push(false);
    }

    fn close(&mut self) {
        self.depth -= 1;
        if self.has_member.pop() == Some(true) {
            self.newline();
        }
        self.out.push('}');
    }

    fn key(&mut self, key: &str) {
        if let Some(has) = self.has_member.last_mut() {
            if *has {
                self.out.push(',');
            }
            *has = true;
        }
        self.newline();
        quote(&mut self.out, key);
        self.out.push_str(": ");
    }

    fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        quote(&mut self.out, value);
    }

    fn num(&mut self, key: &str, value: u64) {
        self.key(key);
        let _ = write!(self.out, "{value}");
    }

    fn bool(&mut self, key: &str, value: bool) {
        self.key(key);
        self.out.push_str(if value { "true" } else { "false" });
    }

    fn null(&mut self, key: &str) {
        self.key(key);
        self.out.push_str("null");
    }

    fn newline(&mut self) {
        self.out.push('\n');
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }

    fn finish(mut self) -> String {
        self.out.push('\n');
        self.out
    }
}

fn quote(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_nested_json() {
        let mut j = Json::default();
        j.open();
        j.str("a", "x\"y\n");
        j.key("b");
        j.open();
        j.num("c", 1);
        j.bool("d", true);
        j.close();
        j.key("e");
        j.open();
        j.close();
        j.null("f");
        j.close();
        assert_eq!(
            j.finish(),
            "{\n  \"a\": \"x\\\"y\\u000a\",\n  \"b\": {\n    \"c\": 1,\n    \"d\": true\n  },\n  \
             \"e\": {},\n  \"f\": null\n}\n"
        );
    }

    #[test]
    fn reads_proc_status_fields() {
        let text = "Name:\tx\nVmHWM:\t   17400 kB\nVmRSS:\t 9000 kB\nThreads:\t12\n";
        assert_eq!(proc_field(text, "VmHWM"), Some(17400));
        assert_eq!(proc_field(text, "VmRSS"), Some(9000));
        assert_eq!(proc_field(text, "Threads"), Some(12));
        assert_eq!(proc_field(text, "VmSwap"), None);
    }

    #[test]
    fn the_page_renders_before_the_client_is_ready() {
        let page = render(9050, None);
        assert!(page.contains("\"state\": \"bootstrapping\""), "{page}");
        assert!(page.contains("\"tor\": null"), "{page}");
        assert!(page.contains("\"listen_port\": 9050"), "{page}");
    }

    #[test]
    fn failures_land_under_their_reply_code() {
        let before = FAILED[5].get();
        failed(5);
        assert_eq!(FAILED[5].get(), before + 1);
        // Out-of-range codes are clamped rather than panicking.
        failed(200);
    }
}
