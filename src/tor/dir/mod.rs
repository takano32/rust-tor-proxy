pub mod authority;
pub mod cache;
pub mod consensus;
pub mod fallback;
pub mod fetch;
pub mod microdesc;
pub mod netdoc;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use authority::KeyCertificate;
use cache::Cache;
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

/// A one-hop circuit to a directory cache.
///
/// Directory documents are fetched over a single hop, the way C Tor bootstraps:
/// the relay learns that somebody is fetching a consensus, which it would learn
/// anyway from any client that has just started.
pub struct DirCircuit {
    channel: Channel,
    circuit: Circuit,
}

impl DirCircuit {
    /// Try random fallback mirrors until one accepts a circuit.
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
        Err(last.unwrap_or_else(|| io::Error::other("no fallback directory answered")))
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
        Ok(Self { channel, circuit })
    }

    pub fn get(&self, path: &str) -> io::Result<Vec<u8>> {
        fetch::get(&self.circuit, path)
    }

    pub fn peer(&self) -> SocketAddrV4 {
        self.channel.peer()
    }

    pub fn close(self) {
        self.circuit.close();
        self.channel.close();
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
    pub fn bootstrap(cache: Cache) -> io::Result<Self> {
        let now = now_unix();
        if let Some(directory) = Self::from_cache(&cache, now) {
            crate::info!(
                "using cached consensus, valid until {}",
                crate::util::format_datetime(directory.consensus.valid_until)
            );
            return Ok(directory);
        }

        let dir_circuit = DirCircuit::to_random_fallback()?;
        crate::info!("fetching consensus from {}", dir_circuit.peer());
        let result = Self::fetch(&cache, &dir_circuit, now);
        dir_circuit.close();
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
        Some(Self {
            consensus,
            certs,
            cache: Cache::new(cache.dir()),
        })
    }

    fn fetch(cache: &Cache, dir_circuit: &DirCircuit, now: u64) -> io::Result<Self> {
        let consensus_raw = dir_circuit.get(CONSENSUS_PATH)?;
        let consensus_text = String::from_utf8(consensus_raw)
            .map_err(|_| invalid_data("consensus is not valid UTF-8"))?;

        // Ask for exactly the certificates this consensus was signed with.
        let wanted = consensus::required_certificates(&consensus_text);
        if wanted.is_empty() {
            return Err(invalid_data(
                "consensus carries no signature from a trusted authority",
            ));
        }
        let path = format!(
            "/tor/keys/fp-sk/{}",
            wanted
                .iter()
                .map(|(id, key)| format!("{}-{}", hex_encode(id), hex_encode(key)))
                .collect::<Vec<_>>()
                .join("+")
        );
        let certs_raw = dir_circuit.get(&path)?;
        let certs_text = String::from_utf8_lossy(&certs_raw).into_owned();
        let certs = authority::parse_key_certificates(&certs_text, now);

        let consensus = consensus::parse_and_verify(&consensus_text, &certs, now)?;

        if let Err(e) = cache.store(CERTS_FILE, certs_text.as_bytes()) {
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

    pub fn certificate_count(&self) -> usize {
        self.certs.len()
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
        let mut missing: Vec<[u8; 32]> = Vec::new();

        for digest in digests {
            match self.cache.load_microdesc(digest) {
                Some(raw) => match microdesc::Microdesc::parse(&String::from_utf8_lossy(&raw)) {
                    Ok(md) if md.digest == *digest => {
                        found.insert(*digest, md);
                    }
                    _ => missing.push(*digest),
                },
                None => missing.push(*digest),
            }
        }

        for batch in missing.chunks(MICRODESCS_PER_REQUEST) {
            let path = format!(
                "/tor/micro/d/{}",
                batch
                    .iter()
                    .map(|d| crate::util::base64_encode_unpadded(d))
                    .collect::<Vec<_>>()
                    .join("-")
            );
            let raw = match dir_circuit.get(&path) {
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
                found.insert(md.digest, md);
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::tor::dir::consensus::{FLAG_EXIT, FLAG_GUARD, FLAG_RUNNING, FLAG_VALID};

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

        let directory = Directory::bootstrap(Cache::new(&dir)).expect("bootstrap");
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
        let mds = directory.microdescs(&wanted, &dir_circuit).expect("microdescs");
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
