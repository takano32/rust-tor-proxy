//! The maintenance thread: everything a long-lived client has to keep doing.
//!
//! A process that runs for days cannot treat the directory as a thing fetched
//! once at start-up. The consensus expires after three hours; the onion
//! service time period turns over at 12:00 UTC and takes every blinded key
//! with it; the microdescriptor cache grows by tens of megabytes each time the
//! network's relays are re-listed; and a guard that was briefly unreachable
//! should be returned to rather than abandoned.
//!
//! One thread does all of it, on a slow tick. Nothing here is on the path of a
//! user's request: a failure is logged and retried, never propagated.

use std::sync::{Arc, Weak};
use std::time::Duration;

use super::certs::now_unix;
use super::client::TorClient;
use crate::ffi::rand;

/// How often the thread wakes to see whether anything is due.
///
/// Short enough that a circuit which has stopped carrying anything is found
/// and replaced within about half a minute of a reader noticing, which is what
/// makes a hung connection recoverable rather than something the application
/// has to time out for itself.
const TICK: Duration = Duration::from_secs(10);

/// First delay after a failed consensus fetch; it doubles up to the cap.
const RETRY_MIN: u64 = 300;
const RETRY_MAX: u64 = 1800;

/// Once the consensus has actually expired, stop backing off and try every
/// minute: at that point the client is running on stale relay data.
const EXPIRED_RETRY: u64 = 60;

/// How long to wait after a directory server answers "not modified". Our
/// window has passed but the authorities have not published yet, so asking
/// again immediately would only spin.
const NOT_MODIFIED_RETRY: u64 = 900;

/// Start the maintenance thread. It holds only a weak reference, so it stops
/// on its own when the client is dropped.
pub fn spawn(client: &Arc<TorClient>) {
    let weak = Arc::downgrade(client);
    let started = std::thread::Builder::new()
        .name("maintain".into())
        .spawn(move || run(weak));
    if let Err(e) = started {
        crate::warn!("could not start the maintenance thread: {e}");
    }
}

fn run(client: Weak<TorClient>) {
    let mut next_refresh = match client.upgrade() {
        Some(client) => plan_refresh(&client),
        None => return,
    };
    let mut backoff = RETRY_MIN;

    // The cache may hold microdescriptors from consensuses that are long gone,
    // which nothing else would ever remove.
    if let Some(client) = client.upgrade() {
        prune(&client);
    }

    loop {
        std::thread::sleep(TICK);
        let Some(client) = client.upgrade() else {
            crate::debug!("maintenance thread stopping: the client is gone");
            return;
        };

        client.retry_primary_guard();
        // A circuit whose reader has been waiting is tested here rather than
        // on the request's own thread, so a probe never delays traffic.
        client.probe_quiet_circuits();
        // Circuits thrown out for being unusable are counted against the guard
        // they were built on here, off the path of any request.
        client.note_bad_circuits();

        if now_unix() < next_refresh {
            continue;
        }
        match client.refresh_consensus() {
            Ok(()) => {
                backoff = RETRY_MIN;
                prune(&client);
                client.prefetch_hsdir_ring();
                next_refresh = plan_refresh(&client);
            }
            // Answered, and the answer was that we already have the newest
            // consensus there is. Nothing is wrong, so the backoff stays put.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                crate::debug!("no newer consensus published yet");
                next_refresh = now_unix() + NOT_MODIFIED_RETRY;
            }
            Err(e) => {
                let live = client.directory().consensus.is_live(now_unix());
                let delay = if live { backoff } else { EXPIRED_RETRY };
                crate::warn!("consensus refresh failed ({e}); retrying in {delay}s");
                next_refresh = now_unix() + delay;
                backoff = (backoff * 2).min(RETRY_MAX);
            }
        }
    }
}

fn prune(client: &TorClient) {
    match client.directory().prune_cache() {
        Ok(report) if report.removed > 0 => crate::info!(
            "pruned the microdescriptor cache: {} kept, {} removed",
            report.kept,
            report.removed
        ),
        Ok(_) => {}
        Err(e) => crate::warn!("could not prune the microdescriptor cache: {e}"),
    }
}

/// When to fetch the next consensus, as a unix time.
fn plan_refresh(client: &TorClient) -> u64 {
    let directory = client.directory();
    let consensus = &directory.consensus;
    let (start, end) = refresh_window(
        consensus.valid_after,
        consensus.fresh_until,
        consensus.valid_until,
    );
    let at = pick_within(start, end);
    crate::debug!(
        "next consensus refresh at {} (window {} to {})",
        crate::util::format_datetime(at),
        crate::util::format_datetime(start),
        crate::util::format_datetime(end)
    );
    at
}

/// The interval dir-spec/client-operation.md tells clients to draw from:
/// from three quarters of the way through the first post-fresh interval, to
/// seven eighths of the time remaining after that before the document expires.
///
/// The point is that every client picks a different moment, so the directory
/// caches are not all asked at once the instant a consensus goes stale.
fn refresh_window(valid_after: u64, fresh_until: u64, valid_until: u64) -> (u64, u64) {
    // A consensus with nonsensical times is not worth arithmetic on; refresh
    // it at once and let the fetch decide.
    if fresh_until <= valid_after || valid_until <= fresh_until {
        return (0, 0);
    }
    let interval = fresh_until - valid_after;
    let start = fresh_until + interval * 3 / 4;
    if start >= valid_until {
        return (start, start);
    }
    let end = start + (valid_until - start) * 7 / 8;
    (start, end)
}

fn pick_within(start: u64, end: u64) -> u64 {
    if end <= start {
        return start;
    }
    match rand::below(end - start) {
        Ok(offset) => start + offset,
        // Without randomness, the middle of the window is still a legal
        // choice; it only costs the spread across clients.
        Err(_) => start + (end - start) / 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from dir-spec/client-operation.md: valid at 1:00,
    /// fresh until 2:00, expiring at 4:00 gives a window of 2:45 to 3:50.
    #[test]
    fn refresh_window_matches_the_specs_example() {
        let hour = 3600;
        let (start, end) = refresh_window(hour, 2 * hour, 4 * hour);
        assert_eq!(start, 2 * hour + 45 * 60, "three quarters of an hour later");
        // Seven eighths of the 75 minutes left is 65 minutes and 37 seconds;
        // the spec's worked example rounds it down to "3:50".
        assert_eq!(end, start + 65 * 60 + 37);
        assert!(end < 4 * hour, "the window closes before the document does");
    }

    #[test]
    fn refresh_window_survives_a_nonsensical_consensus() {
        assert_eq!(refresh_window(100, 100, 200), (0, 0));
        assert_eq!(refresh_window(100, 50, 200), (0, 0));
        assert_eq!(refresh_window(100, 200, 200), (0, 0));
        // Fresh for so long that the window would start after expiry.
        let (start, end) = refresh_window(0, 1000, 1100);
        assert_eq!(start, end, "no room to choose within");
    }

    /// Every draw has to land inside the window, and the draws have to differ:
    /// a fixed choice would put every client on the network at one instant.
    #[test]
    fn refresh_times_are_spread_across_the_window() {
        let (start, end) = refresh_window(3600, 7200, 14400);
        let picks: Vec<u64> = (0..64).map(|_| pick_within(start, end)).collect();
        assert!(picks.iter().all(|&t| (start..end).contains(&t)));
        let distinct: std::collections::HashSet<u64> = picks.iter().copied().collect();
        assert!(
            distinct.len() > 32,
            "only {} distinct times",
            distinct.len()
        );
        // A degenerate window is not an error.
        assert_eq!(pick_within(500, 500), 500);
        assert_eq!(pick_within(500, 400), 500);
    }
}
