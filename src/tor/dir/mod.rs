pub mod authority;
pub mod cache;
pub mod consensus;
pub mod diff;
pub mod fallback;
pub mod fetch;
pub mod microdesc;
pub mod netdoc;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use authority::KeyCertificate;
use cache::{Cache, PruneReport};
use consensus::Consensus;
use microdesc::Microdesc;

use super::certs::now_unix;
use super::channel::Channel;
use super::circuit::Circuit;
use crate::ffi::rand;
use crate::util::{hex_encode, invalid_data};

const CONSENSUS_PATH: &str = "/tor/status-vote/current/consensus-microdesc";
const CONSENSUS_FILE: &str = "consensus";
const CERTS_FILE: &str = "certs";

/// A directory request URL may not name more than this many microdescriptors.
const MICRODESCS_PER_REQUEST: usize = 92;

/// Above this many batches, report progress: the fetch will take a while.
const LOUD_FETCH_BATCHES: usize = 4;

/// A one-hop circuit to a directory cache.
///
/// Directory documents are fetched over a single hop, the way C Tor bootstraps:
/// the relay learns that somebody is fetching a consensus, which it would learn
/// anyway from any client that has just started.
pub struct DirCircuit {
    channel: Channel,
    circuit: Circuit,
    /// False when the channel belongs to someone else (the guard), in which
    /// case closing this must not close the channel.
    owns_channel: bool,
}

impl DirCircuit {
    /// Try random fallback mirrors until one accepts a circuit, then fall
    /// back to the directory authorities themselves.
    pub fn to_random_fallback() -> io::Result<Self> {
        let dirs = fallback::FALLBACK_DIRS;
        let mut last: Option<io::Error> = None;
        for _ in 0..10 {
            let index = rand::below(dirs.len() as u64)? as usize;
            let entry = &dirs[index];
            let addr = SocketAddrV4::new(Ipv4Addr::from(entry.ipv4), entry.or_port);
            match Self::to(addr) {
                Ok(dir) => return Ok(dir),
                Err(e) => {
                    crate::debug!("fallback {addr}: {e}");
                    last = Some(e);
                }
            }
        }

        // The authorities are a last resort: they are few, so leaning on them
        // is both slow for us and rude to them.
        crate::warn!("no fallback mirror answered; trying the authorities");
        for auth in authority::AUTHORITIES {
            let addr = SocketAddrV4::new(Ipv4Addr::from(auth.ipv4), auth.or_port);
            match Self::to(addr) {
                Ok(dir) => {
                    crate::info!("using directory authority {}", auth.nickname);
                    return Ok(dir);
                }
                Err(e) => {
                    crate::debug!("authority {} ({addr}): {e}", auth.nickname);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no directory server answered")))
    }

    pub fn to(addr: SocketAddrV4) -> io::Result<Self> {
        let channel = Channel::connect(addr, None)?;
        let circuit = match Circuit::create_fast(&channel) {
            Ok(circuit) => circuit,
            Err(e) => {
                channel.close();
                return Err(e);
            }
        };
        Ok(Self {
            channel,
            circuit,
            owns_channel: true,
        })
    }

    /// A directory circuit on a channel that is already open, so that a
    /// directory fetch through the guard does not need a second connection.
    pub fn on(channel: Channel) -> io::Result<Self> {
        let circuit = Circuit::create_fast(&channel)?;
        Ok(Self {
            channel,
            circuit,
            owns_channel: false,
        })
    }

    pub fn get(&self, path: &str) -> io::Result<Vec<u8>> {
        fetch::get(&self.circuit, path)
    }

    pub fn get_with(&self, path: &str, headers: &[(&str, String)]) -> io::Result<Vec<u8>> {
        fetch::get_with(&self.circuit, path, headers)
    }

    /// Several paths at once, on separate streams over this one circuit.
    pub fn get_parallel(&self, paths: &[String]) -> Vec<io::Result<Vec<u8>>> {
        fetch::get_parallel(&self.circuit, paths)
    }

    pub fn peer(&self) -> SocketAddrV4 {
        self.channel.peer()
    }

    pub fn close(self) {
        self.circuit.close();
        if self.owns_channel {
            self.channel.close();
        }
    }
}

/// A verified view of the Tor network.
pub struct Directory {
    pub consensus: Consensus,
    certs: Vec<KeyCertificate>,
    cache: Cache,
}

impl Directory {
    /// Load a live consensus from the cache, or fetch and verify a new one.
    ///
    /// `open_circuit` supplies the one-hop directory circuit, so that a client
    /// which already knows a guard can bootstrap through it rather than
    /// opening a second connection to a fallback mirror.
    pub fn bootstrap(
        cache: Cache,
        open_circuit: impl Fn() -> io::Result<DirCircuit>,
    ) -> io::Result<Self> {
        let now = now_unix();
        if let Some(directory) = Self::from_cache(&cache, now) {
            crate::info!("using cached consensus: {}", directory.summary());
            return Ok(directory);
        }

        // Even an expired cached consensus is worth keeping hold of: the
        // server can send a diff against it instead of three megabytes.
        let stale = cache
            .load(CONSENSUS_FILE)
            .and_then(|raw| String::from_utf8(raw).ok());
        let certs = cache
            .load(CERTS_FILE)
            .map(|raw| authority::parse_key_certificates(&String::from_utf8_lossy(&raw), now))
            .unwrap_or_default();

        let dir_circuit = open_circuit()?;
        crate::info!("fetching consensus from {}", dir_circuit.peer());
        let mut result = Self::download(&cache, &dir_circuit, now, stale.as_deref(), &certs);
        if result
            .as_ref()
            .is_err_and(|e| e.kind() == io::ErrorKind::AlreadyExists)
        {
            // The server says our copy is current, but we got here because it
            // will not verify or has expired. Ask for it in full.
            crate::debug!("the cached consensus is unusable despite being current; refetching");
            result = Self::download(&cache, &dir_circuit, now, None, &certs);
        }
        dir_circuit.close();
        if let Ok(directory) = &result {
            crate::info!("consensus verified: {}", directory.summary());
        }
        result
    }

    fn from_cache(cache: &Cache, now: u64) -> Option<Self> {
        let certs_raw = cache.load(CERTS_FILE)?;
        let consensus_raw = cache.load(CONSENSUS_FILE)?;
        let certs = authority::parse_key_certificates(&String::from_utf8_lossy(&certs_raw), now);
        let consensus =
            consensus::parse_and_verify(&String::from_utf8_lossy(&consensus_raw), &certs, now)
                .map_err(|e| crate::debug!("cached consensus unusable: {e}"))
                .ok()?;
        if !consensus.is_live(now) {
            crate::debug!("cached consensus is no longer valid");
            return None;
        }
        Some(Self {
            consensus,
            certs,
            cache: Cache::new(cache.dir()),
        })
    }

    /// Fetch a newer consensus, asking for a diff against the one we hold.
    ///
    /// Returns a whole new `Directory`; the caller swaps it into place, so a
    /// failed refresh leaves the running client on the consensus it had.
    pub fn refresh(&self, dir_circuit: &DirCircuit, now: u64) -> io::Result<Self> {
        let base = self
            .cache
            .load(CONSENSUS_FILE)
            .and_then(|raw| String::from_utf8(raw).ok());
        let next = Self::download(&self.cache, dir_circuit, now, base.as_deref(), &self.certs)?;
        if next.consensus.valid_after <= self.consensus.valid_after {
            return Err(invalid_data(format!(
                "directory server offered a consensus from {}, no newer than the one we hold",
                crate::util::format_datetime(next.consensus.valid_after)
            )));
        }
        Ok(next)
    }

    /// Download, verify and cache a consensus.
    ///
    /// When `base` is present the request carries `X-Or-Diff-From-Consensus`;
    /// a server that has the matching diff sends a few kilobytes of ed script
    /// rather than the whole document. Anything that goes wrong with the diff
    /// -- a hash we do not recognise, a script that will not apply, a result
    /// that fails verification -- falls back to fetching the document whole,
    /// because a diff is an optimisation and never a source of truth.
    fn download(
        cache: &Cache,
        dir_circuit: &DirCircuit,
        now: u64,
        base: Option<&str>,
        known_certs: &[KeyCertificate],
    ) -> io::Result<Self> {
        let consensus_text = match base {
            Some(base) => match Self::download_diffed(dir_circuit, base) {
                Ok(text) => text,
                // "Not modified": we already hold the current consensus, so
                // there is nothing to download and nothing has gone wrong.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(e),
                Err(e) => {
                    crate::warn!("consensus diff unusable ({e}); fetching the whole document");
                    Self::download_full(dir_circuit)?
                }
            },
            None => Self::download_full(dir_circuit)?,
        };

        let certs = Self::certificates_for(dir_circuit, &consensus_text, now, known_certs)?;
        let consensus = consensus::parse_and_verify(&consensus_text, &certs, now)?;

        // Only cache once the consensus has verified, so neither file can be
        // left holding a document that would fail on the next start-up.
        if let Err(e) = cache.store(CERTS_FILE, authority::serialize(&certs).as_bytes()) {
            crate::warn!("could not cache key certificates: {e}");
        }
        if let Err(e) = cache.store(CONSENSUS_FILE, consensus_text.as_bytes()) {
            crate::warn!("could not cache consensus: {e}");
        }
        Ok(Self {
            consensus,
            certs,
            cache: Cache::new(cache.dir()),
        })
    }

    fn download_full(dir_circuit: &DirCircuit) -> io::Result<String> {
        let raw = dir_circuit.get(CONSENSUS_PATH)?;
        String::from_utf8(raw).map_err(|_| invalid_data("consensus is not valid UTF-8"))
    }

    /// Ask for a diff, and accept the answer whichever form it takes: the
    /// server is free to send the whole document when it has no matching diff.
    fn download_diffed(dir_circuit: &DirCircuit, base: &str) -> io::Result<String> {
        // The header names the digest of the *signed part* -- everything up to
        // and including the first `directory-signature ` -- not of the whole
        // document. That is what lets one diff serve clients whose copies
        // carry different sets of authority signatures.
        let headers = [("X-Or-Diff-From-Consensus", diff::signed_part_digest(base))];
        let raw = dir_circuit.get_with(CONSENSUS_PATH, &headers)?;
        let text = String::from_utf8(raw).map_err(|_| invalid_data("consensus is not UTF-8"))?;
        if !text.starts_with("network-status-diff-version") {
            return Ok(text);
        }
        let patched = diff::apply(base, &text)?;
        crate::info!(
            "consensus updated by diff: {} bytes of script for {} bytes of document",
            text.len(),
            patched.len()
        );
        Ok(patched)
    }

    /// The key certificates this consensus is signed with, reusing the ones we
    /// already hold and fetching only what is missing.
    ///
    /// Everything is rebuilt from text rather than moved, because a parsed
    /// certificate owns an OpenSSL key that cannot be cheaply duplicated --
    /// and re-parsing a dozen certificates once an hour costs nothing.
    fn certificates_for(
        dir_circuit: &DirCircuit,
        consensus_text: &str,
        now: u64,
        known: &[KeyCertificate],
    ) -> io::Result<Vec<KeyCertificate>> {
        let wanted = consensus::required_certificates(consensus_text);
        if wanted.is_empty() {
            return Err(invalid_data(
                "consensus carries no signature from a trusted authority",
            ));
        }
        let missing: Vec<([u8; 20], [u8; 20])> = wanted
            .iter()
            .copied()
            .filter(|(id, key)| !known.iter().any(|c| c.matches(id, key)))
            .collect();

        let mut text = authority::serialize(known);
        if missing.is_empty() {
            crate::debug!("every signing key this consensus uses is already cached");
        } else {
            let path = format!(
                "/tor/keys/fp-sk/{}",
                missing
                    .iter()
                    .map(|(id, key)| format!("{}-{}", hex_encode(id), hex_encode(key)))
                    .collect::<Vec<_>>()
                    .join("+")
            );
            let fetched = dir_circuit.get(&path)?;
            text.push_str(&String::from_utf8_lossy(&fetched));
        }
        Ok(authority::parse_key_certificates(&text, now))
    }

    /// Delete cached microdescriptors this consensus no longer names.
    pub fn prune_cache(&self) -> io::Result<PruneReport> {
        let keep: HashSet<[u8; 32]> = self
            .consensus
            .routers
            .iter()
            .map(|r| r.microdesc_digest)
            .collect();
        self.cache.prune_microdescs(&keep)
    }

    pub fn certificate_count(&self) -> usize {
        self.certs.len()
    }

    /// A one-line description for the startup log.
    pub fn summary(&self) -> String {
        use consensus::{FLAG_EXIT, FLAG_GUARD, FLAG_RUNNING, FLAG_VALID};
        let c = &self.consensus;
        format!(
            "{} relays ({} guards, {} exits), {} authority certificates, \
             valid-after {}, fresh-until {}, valid-until {}",
            c.routers.len(),
            c.count_with(FLAG_GUARD | FLAG_RUNNING | FLAG_VALID),
            c.count_with(FLAG_EXIT | FLAG_RUNNING | FLAG_VALID),
            self.certificate_count(),
            crate::util::format_datetime(c.valid_after),
            crate::util::format_datetime(c.fresh_until),
            crate::util::format_datetime(c.valid_until),
        )
    }

    /// Fetch the microdescriptors for `digests`, using the cache where
    /// possible. Entries whose text does not hash to the digest the consensus
    /// promised are dropped.
    pub fn microdescs(
        &self,
        digests: &[[u8; 32]],
        dir_circuit: &DirCircuit,
    ) -> io::Result<HashMap<[u8; 32], Microdesc>> {
        let mut found: HashMap<[u8; 32], Microdesc> = HashMap::new();
        self.stream_microdescs(digests, dir_circuit, &mut |digest, md| {
            found.insert(digest, md);
        });
        Ok(found)
    }

    /// Just the Ed25519 identity of each relay, for the HSDir hash ring.
    ///
    /// The ring needs every HSDir in the consensus, which is thousands of
    /// microdescriptors; keeping them would cost far more memory than this
    /// whole program is allowed. Relays whose microdescriptor has no `id
    /// ed25519` line cannot be placed on the ring at all, so they are simply
    /// absent from the result.
    pub fn microdesc_ed_ids(
        &self,
        digests: &[[u8; 32]],
        dir_circuit: &DirCircuit,
    ) -> HashMap<[u8; 32], [u8; 32]> {
        let mut found: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        self.stream_microdescs(digests, dir_circuit, &mut |digest, md| {
            if let Some(ed) = md.ed_identity {
                found.insert(digest, ed);
            }
        });
        found
    }

    /// The shared machinery: serve what the disk cache has, fetch the rest in
    /// batches, and hand each microdescriptor to `on_each` as it arrives
    /// rather than accumulating them here.
    fn stream_microdescs(
        &self,
        digests: &[[u8; 32]],
        dir_circuit: &DirCircuit,
        on_each: &mut dyn FnMut([u8; 32], Microdesc),
    ) {
        let mut missing: Vec<[u8; 32]> = Vec::new();
        for digest in digests {
            match self.cache.load_microdesc(digest) {
                Some(raw) => match microdesc::Microdesc::parse(&String::from_utf8_lossy(&raw)) {
                    Ok(md) if md.digest == *digest => on_each(*digest, md),
                    _ => missing.push(*digest),
                },
                None => missing.push(*digest),
            }
        }

        let batches: Vec<&[[u8; 32]]> = missing.chunks(MICRODESCS_PER_REQUEST).collect();
        let paths: Vec<String> = batches
            .iter()
            .map(|batch| {
                format!(
                    "/tor/micro/d/{}",
                    batch
                        .iter()
                        .map(|d| crate::util::base64_encode_unpadded(d))
                        .collect::<Vec<_>>()
                        .join("-")
                )
            })
            .collect();
        // A handful of relays is routine; thousands means the HSDir table is
        // being built, which takes long enough to deserve a word.
        if batches.len() > LOUD_FETCH_BATCHES {
            crate::info!(
                "fetching {} microdescriptors in {} batches, {} at a time",
                missing.len(),
                batches.len(),
                fetch::MAX_PARALLEL_REQUESTS
            );
        }

        // Several batches share the one circuit, each on its own stream: the
        // round trips overlap instead of queueing behind one another.
        for (batch, result) in batches.iter().zip(dir_circuit.get_parallel(&paths)) {
            let raw = match result {
                Ok(raw) => raw,
                Err(e) => {
                    crate::warn!("microdescriptor batch failed: {e}");
                    continue;
                }
            };
            let text = String::from_utf8_lossy(&raw).into_owned();
            for (body, md) in microdesc::parse_batch(&text) {
                if !batch.contains(&md.digest) {
                    // The consensus names microdescriptors by their digest, so
                    // anything else means the cache substituted a document.
                    crate::warn!("directory cache returned an unrequested microdescriptor");
                    continue;
                }
                if let Err(e) = self.cache.store_microdesc(&md.digest, body.as_bytes()) {
                    crate::debug!("could not cache microdescriptor: {e}");
                }
                on_each(md.digest, md);
            }
        }
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::tor::dir::consensus::{FLAG_EXIT, FLAG_GUARD, FLAG_RUNNING, FLAG_VALID};

    /// Live check: ask a real directory cache for a diff against the
    /// consensus we hold.
    ///
    /// Which of the two answers comes back depends on the clock: within the
    /// hour the server has nothing newer to offer, and after it a diff should
    /// arrive. Both are correct; what this proves is that the request is
    /// well-formed, that the header digest is the one the server indexes by,
    /// and that whatever comes back verifies.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn asks_for_a_consensus_diff() {
        crate::log::init();
        let dir = std::env::temp_dir().join(format!("tor-diff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let directory = Directory::bootstrap(Cache::new(&dir), DirCircuit::to_random_fallback)
            .expect("bootstrap");
        let held = directory.consensus.valid_after;
        println!(
            "holding a consensus valid after {}, digest {}",
            crate::util::format_datetime(held),
            &diff::signed_part_digest(
                &String::from_utf8(Cache::new(&dir).load(CONSENSUS_FILE).unwrap()).unwrap()
            )[..16]
        );

        let dir_circuit = DirCircuit::to_random_fallback().expect("dir circuit");
        println!("asking {}", dir_circuit.peer());
        let result = directory.refresh(&dir_circuit, now_unix());
        dir_circuit.close();

        match result {
            Ok(next) => {
                println!("refreshed: {}", next.summary());
                assert!(
                    next.consensus.valid_after > held,
                    "a refresh must move forwards"
                );
                assert!(next.consensus.routers.len() > 1000);
            }
            Err(e) => {
                // The only acceptable failure is "nothing newer exists yet",
                // which a server states either as HTTP 304 -- proof that it
                // recognised our digest -- or by sending the same consensus
                // back.
                println!("no newer consensus: {e}");
                assert!(
                    e.kind() == io::ErrorKind::AlreadyExists
                        || e.to_string().contains("no newer than"),
                    "{e}"
                );
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live check: bootstrap a signature-verified consensus and fetch a few
    /// microdescriptors from it.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn bootstraps_a_verified_consensus() {
        crate::log::init();
        let dir = std::env::temp_dir().join(format!("tor-bootstrap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let directory = Directory::bootstrap(Cache::new(&dir), DirCircuit::to_random_fallback)
            .expect("bootstrap");
        let consensus = &directory.consensus;
        println!(
            "consensus: {} routers, {} guards, {} exits, {} authority certificates",
            consensus.routers.len(),
            consensus.count_with(FLAG_GUARD | FLAG_RUNNING | FLAG_VALID),
            consensus.count_with(FLAG_EXIT | FLAG_RUNNING | FLAG_VALID),
            directory.certificate_count()
        );
        println!(
            "valid-after {}  fresh-until {}  valid-until {}",
            crate::util::format_datetime(consensus.valid_after),
            crate::util::format_datetime(consensus.fresh_until),
            crate::util::format_datetime(consensus.valid_until)
        );
        assert!(consensus.routers.len() > 1000, "consensus looks too small");
        assert!(consensus.count_with(FLAG_GUARD) > 100);
        assert!(consensus.count_with(FLAG_EXIT) > 10);
        assert!(consensus.is_live(now_unix()));

        // A second bootstrap must be served entirely from the cache.
        let cached = Directory::from_cache(&Cache::new(&dir), now_unix())
            .expect("the freshly written cache should verify");
        assert_eq!(cached.consensus.routers.len(), consensus.routers.len());

        // Fetch a handful of microdescriptors and check they hash as promised.
        let wanted: Vec<[u8; 32]> = consensus
            .routers
            .iter()
            .filter(|r| r.has(FLAG_GUARD | FLAG_RUNNING | FLAG_VALID))
            .take(5)
            .map(|r| r.microdesc_digest)
            .collect();
        let dir_circuit = DirCircuit::to_random_fallback().expect("dir circuit");
        let mds = directory
            .microdescs(&wanted, &dir_circuit)
            .expect("microdescs");
        dir_circuit.close();
        println!("fetched {} of {} microdescriptors", mds.len(), wanted.len());
        assert!(!mds.is_empty());
        for (digest, md) in &mds {
            assert_eq!(&md.digest, digest);
            assert_ne!(md.ntor_onion_key, [0u8; 32]);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
