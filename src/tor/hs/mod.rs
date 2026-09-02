//! Version 3 onion services, client side (rend-spec).
//!
//! The shape of a `.onion` connection: derive the blinded key for the current
//! time period from the address, work out which directory nodes hold the
//! service's descriptor, fetch and decrypt it, then use the introduction
//! points it lists to arrange a meeting at a rendezvous point of our choosing.

pub mod address;
pub mod blind;
pub mod descriptor;
pub mod hsdir;
pub mod ntor;
pub mod rendezvous;

/// `INT_8(x)`: the eight-byte big-endian encoding rend-spec writes that way.
/// Not to be confused with tor-spec's one-byte `INT8`.
pub fn int8(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// `MAC(key, msg) = H(INT_8(len(key)) | key | msg)`.
///
/// The key comes first, as in C Tor's `crypto_mac_sha3_256(out, key, msg)`.
/// rend-spec writes calls like `MAC(rend_secret_hs_input, t_hsenc)`, where the
/// long value is the key and the short tweak string is the message -- which
/// reads backwards until you know that.
pub fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + key.len() + msg.len());
    input.extend_from_slice(&int8(key.len() as u64));
    input.extend_from_slice(key);
    input.extend_from_slice(msg);
    crate::ffi::hash::sha3_256(&input)
}

#[cfg(test)]
mod live_tests {
    use super::address::OnionAddress;
    use super::hsdir;
    use crate::tor::client::TorClient;
    use crate::util::hex_encode;

    /// A service that is expected to stay up, used by the live tests here and
    /// in the modules above.
    pub const TORPROJECT_ONION: &str =
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    /// Live check: from a real consensus, work out which directory nodes hold
    /// a known service's descriptor.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn finds_the_responsible_hsdirs_for_a_known_onion() {
        crate::log::init();
        let dir = std::env::temp_dir().join(format!("tor-hsdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let client = TorClient::bootstrap(dir.clone()).expect("bootstrap");
        let address = OnionAddress::parse(TORPROJECT_ONION).expect("address");

        let start = std::time::Instant::now();
        let ring = client.hsdir_ring().expect("hsdir ring");
        println!(
            "ring built in {:.1}s, time period {} of {} minutes",
            start.elapsed().as_secs_f32(),
            ring.period.number,
            ring.period.length
        );
        let directory = client.consensus();
        println!(
            "shared random value {}",
            hex_encode(&hsdir::shared_random_value(
                &directory.consensus,
                &ring.period
            ))
        );

        let blinded = ring
            .period
            .blinded_key(&address.public_key)
            .expect("blinded key");
        println!("A'            = {}", hex_encode(&blinded));
        println!(
            "subcredential = {}",
            hex_encode(&address.subcredential(&blinded))
        );

        let responsible = ring.responsible_for(&blinded);
        assert_eq!(responsible.len(), 6, "two replicas of three HSDirs");
        for (index, identity) in responsible.iter().enumerate() {
            let status = directory
                .consensus
                .routers
                .iter()
                .find(|r| &r.identity == identity)
                .expect("a responsible HSDir must be in the consensus");
            println!(
                "hsdir {}: {} at {}:{}",
                index + 1,
                hex_encode(identity),
                std::net::Ipv4Addr::from(status.ipv4),
                status.or_port
            );
        }

        // Stable for this period, and different for a different service.
        assert_eq!(responsible, ring.responsible_for(&blinded));
        let other = ring.period.blinded_key(&[0x11u8; 32]);
        if let Ok(other) = other {
            assert_ne!(responsible, ring.responsible_for(&other));
        }

        // The second call must come from the cached ring, not refetch it.
        let again = std::time::Instant::now();
        let _ = client.hsdir_ring().expect("cached ring");
        assert!(again.elapsed().as_secs() < 2, "the ring should be cached");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live check: fetch, verify and decrypt a real descriptor, and report
    /// what it says.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn fetches_and_decrypts_a_real_descriptor() {
        crate::log::init();
        let dir = std::env::temp_dir().join(format!("tor-hsdesc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let client = TorClient::bootstrap(dir.clone()).expect("bootstrap");
        let address = OnionAddress::parse(TORPROJECT_ONION).expect("address");

        let start = std::time::Instant::now();
        let descriptor = client.descriptor(&address).expect("descriptor");
        println!(
            "descriptor in {:.1}s: revision {}, lifetime {} minutes, {} introduction points",
            start.elapsed().as_secs_f32(),
            descriptor.revision_counter,
            descriptor.lifetime_minutes,
            descriptor.intro_points.len()
        );
        assert!(!descriptor.intro_points.is_empty());
        assert!(descriptor.intro_points.len() <= 20);
        for (index, point) in descriptor.intro_points.iter().enumerate() {
            println!(
                "  intro {}: {} auth-key {} enc-key {}",
                index + 1,
                point.relay.addr,
                hex_encode(&point.auth_key[..8]),
                hex_encode(&point.enc_key[..8])
            );
            assert_ne!(point.auth_key, [0u8; 32]);
            assert_ne!(point.enc_key, [0u8; 32]);
            assert_ne!(point.relay.ntor_onion_key, [0u8; 32]);
        }

        // The second call is served from the in-memory cache.
        let again = std::time::Instant::now();
        let cached = client.descriptor(&address).expect("cached descriptor");
        assert!(again.elapsed().as_secs() < 2, "descriptor should be cached");
        assert_eq!(cached.revision_counter, descriptor.revision_counter);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live check: the whole rendezvous dance, ending in an HTTP request to a
    /// real onion service.
    ///
    /// Run with `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "requires network access to the Tor network"]
    fn connects_to_a_real_onion_service() {
        use std::io::{Read, Write};

        crate::log::init();
        let dir = std::env::temp_dir().join(format!("tor-onion-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let client = TorClient::bootstrap(dir.clone()).expect("bootstrap");
        let address = OnionAddress::parse(TORPROJECT_ONION).expect("address");

        let start = std::time::Instant::now();
        let mut stream = client.connect_onion(&address, 80).expect("connect_onion");
        println!(
            "rendezvous established in {:.1}s",
            start.elapsed().as_secs_f32()
        );

        stream
            .write_all(
                format!("GET / HTTP/1.0\r\nHost: {TORPROJECT_ONION}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        stream.flush().unwrap();

        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("read failed: {e}"),
            }
        }
        let text = String::from_utf8_lossy(&response);
        println!("--- response ---\n{}", &text[..text.len().min(300)]);
        assert!(text.starts_with("HTTP/1."), "not an HTTP response");
        assert!(response.len() > 100, "response looks truncated");

        // A second stream must ride the same rendezvous circuit.
        let second = std::time::Instant::now();
        let again = client.connect_onion(&address, 80).expect("second connect");
        println!("second stream in {:.2}s", second.elapsed().as_secs_f32());
        assert!(
            second.elapsed().as_secs() < 20,
            "the circuit should be reused"
        );
        again.close();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
