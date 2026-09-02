//! The circuit-extension handshakes (tor-spec/create-created-cells.md) and
//! the KDFs that turn their output into circuit keys
//! (tor-spec/setting-circuit-keys.md).
//!
//! `ntor` is the handshake used for every real hop. `CREATE_FAST` is the
//! bootstrap case: a one-hop circuit to a directory cache, built before we
//! know any relay's `KP_onion_ntor`, whose security rests on the TLS
//! connection and the CERTS cell alone.
//!
//! Throughout, `H(x, t)` is HMAC-SHA256 over message `x` with key `t`.

use std::io;

use crate::ffi::hash::sha1;
use crate::ffi::hmac::hmac_sha256;
use crate::ffi::rand;
use crate::ffi::x25519::EphemeralSecret;
use crate::ffi::constant_time_eq;
use crate::util::invalid_data;

/// HTYPE for ntor in CREATE2 / EXTEND2.
pub const HANDSHAKE_TYPE_NTOR: u16 = 0x0002;

/// Length of the client's onion skin: NODEID | KEYID | X.
pub const CLIENT_HANDSHAKE_LEN: usize = 20 + 32 + 32;
/// Length of the relay's reply: Y | AUTH.
pub const SERVER_HANDSHAKE_LEN: usize = 32 + 32;

const PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";
const SERVER_STRING: &[u8] = b"Server";

/// The per-hop key material taken from the KDF output.
pub struct CircuitKeys {
    /// Seed for the running digest of cells we send to this hop.
    pub df: [u8; 20],
    /// Seed for the running digest of cells this hop sends back.
    pub db: [u8; 20],
    /// Forward (client to relay) AES-128-CTR key.
    pub kf: [u8; 16],
    /// Backward (relay to client) AES-128-CTR key.
    pub kb: [u8; 16],
}

/// Client state between sending the onion skin and receiving the reply.
pub struct NtorClient {
    secret: EphemeralSecret,
    x_pub: [u8; 32],
    node_id: [u8; 20],
    onion_key: [u8; 32],
}

impl NtorClient {
    /// Start a handshake with the relay whose RSA identity digest is
    /// `node_id` and whose ntor onion key is `onion_key`.
    ///
    /// Returns the client handshake bytes to put in CREATE2 or EXTEND2.
    pub fn new(node_id: &[u8; 20], onion_key: &[u8; 32]) -> io::Result<(Self, Vec<u8>)> {
        let secret = EphemeralSecret::generate()?;
        let x_pub = secret.public_key()?;

        let mut skin = Vec::with_capacity(CLIENT_HANDSHAKE_LEN);
        skin.extend_from_slice(node_id);
        skin.extend_from_slice(onion_key);
        skin.extend_from_slice(&x_pub);

        Ok((
            Self {
                secret,
                x_pub,
                node_id: *node_id,
                onion_key: *onion_key,
            },
            skin,
        ))
    }

    /// Check the relay's reply and derive the circuit keys.
    pub fn finish(&self, reply: &[u8]) -> io::Result<CircuitKeys> {
        if reply.len() < SERVER_HANDSHAKE_LEN {
            return Err(invalid_data("ntor reply is too short"));
        }
        let mut y_pub = [0u8; 32];
        y_pub.copy_from_slice(&reply[..32]);
        let auth = &reply[32..64];

        // Both EXP() results must be non-degenerate; OpenSSL's X25519 rejects
        // an all-zero shared secret for us.
        let exp_yx = self.secret.diffie_hellman(&y_pub)?;
        let exp_bx = self.secret.diffie_hellman(&self.onion_key)?;

        let mut secret_input = Vec::with_capacity(32 * 5 + 20 + PROTOID.len());
        secret_input.extend_from_slice(&exp_yx);
        secret_input.extend_from_slice(&exp_bx);
        secret_input.extend_from_slice(&self.node_id);
        secret_input.extend_from_slice(&self.onion_key);
        secret_input.extend_from_slice(&self.x_pub);
        secret_input.extend_from_slice(&y_pub);
        secret_input.extend_from_slice(PROTOID);

        let key_seed = hmac_sha256(T_KEY, &secret_input);
        let verify = hmac_sha256(T_VERIFY, &secret_input);

        let mut auth_input = Vec::with_capacity(32 + 20 + 32 * 2 + PROTOID.len() + 6);
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(&self.node_id);
        auth_input.extend_from_slice(&self.onion_key);
        auth_input.extend_from_slice(&y_pub);
        auth_input.extend_from_slice(&self.x_pub);
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(SERVER_STRING);

        let expected_auth = hmac_sha256(T_MAC, &auth_input);
        if !constant_time_eq(&expected_auth, auth) {
            return Err(invalid_data("ntor AUTH mismatch: relay did not prove its key"));
        }

        Ok(derive_keys(&key_seed))
    }
}

/// KDF-RFC5869 with SHA-256: `K_1 = H(m_expand | 1, KEY_SEED)` and
/// `K_(i+1) = H(K_i | m_expand | i+1, KEY_SEED)`.
pub fn kdf_rfc5869(key_seed: &[u8], m_expand: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + 32);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut message = Vec::with_capacity(prev.len() + m_expand.len() + 1);
        message.extend_from_slice(&prev);
        message.extend_from_slice(m_expand);
        message.push(counter);
        let block = hmac_sha256(key_seed, &message);
        out.extend_from_slice(&block);
        prev = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

fn derive_keys(key_seed: &[u8]) -> CircuitKeys {
    // Df(20) | Db(20) | Kf(16) | Kb(16); the trailing nonce is unused here.
    let stream = kdf_rfc5869(key_seed, M_EXPAND, 72);
    let mut keys = CircuitKeys {
        df: [0u8; 20],
        db: [0u8; 20],
        kf: [0u8; 16],
        kb: [0u8; 16],
    };
    keys.df.copy_from_slice(&stream[0..20]);
    keys.db.copy_from_slice(&stream[20..40]);
    keys.kf.copy_from_slice(&stream[40..56]);
    keys.kb.copy_from_slice(&stream[56..72]);
    keys
}

/// Key material length for CREATE_FAST, in both directions.
pub const CREATE_FAST_LEN: usize = 20;
/// CREATED_FAST carries `Y` followed by the derivative key data `KH`.
pub const CREATED_FAST_LEN: usize = 40;

/// The client half of a CREATE_FAST handshake.
pub struct CreateFastClient {
    x: [u8; CREATE_FAST_LEN],
}

impl CreateFastClient {
    pub fn new() -> io::Result<(Self, Vec<u8>)> {
        let x: [u8; CREATE_FAST_LEN] = rand::bytes()?;
        Ok((Self { x }, x.to_vec()))
    }

    pub fn finish(&self, reply: &[u8]) -> io::Result<CircuitKeys> {
        if reply.len() < CREATED_FAST_LEN {
            return Err(invalid_data("CREATED_FAST reply is too short"));
        }
        let mut k0 = Vec::with_capacity(CREATE_FAST_LEN * 2);
        k0.extend_from_slice(&self.x);
        k0.extend_from_slice(&reply[..CREATE_FAST_LEN]);

        // KH(20) | Df(20) | Db(20) | Kf(16) | Kb(16)
        let stream = kdf_tor(&k0, 92);
        if !constant_time_eq(&stream[..20], &reply[CREATE_FAST_LEN..CREATED_FAST_LEN]) {
            return Err(invalid_data(
                "CREATED_FAST KH mismatch: relay did not derive the same keys",
            ));
        }
        let mut keys = CircuitKeys {
            df: [0u8; 20],
            db: [0u8; 20],
            kf: [0u8; 16],
            kb: [0u8; 16],
        };
        keys.df.copy_from_slice(&stream[20..40]);
        keys.db.copy_from_slice(&stream[40..60]);
        keys.kf.copy_from_slice(&stream[60..76]);
        keys.kb.copy_from_slice(&stream[76..92]);
        Ok(keys)
    }
}

/// KDF-TOR: `K = SHA1(K0 | [00]) | SHA1(K0 | [01]) | ...`.
pub fn kdf_tor(k0: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len <= 20 * 256, "KDF-TOR cannot produce that much output");
    let mut out = Vec::with_capacity(out_len + 20);
    let mut counter: u8 = 0;
    while out.len() < out_len {
        let mut message = Vec::with_capacity(k0.len() + 1);
        message.extend_from_slice(k0);
        message.push(counter);
        out.extend_from_slice(&sha1(&message));
        counter += 1;
    }
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Play the relay's half of the handshake so the client half can be
    /// checked end to end: both sides must reach the same KEY_SEED, and the
    /// client must reject a forged AUTH.
    fn server_reply(
        onion_secret: &EphemeralSecret,
        node_id: &[u8; 20],
        skin: &[u8],
    ) -> (Vec<u8>, CircuitKeys) {
        let b_pub = onion_secret.public_key().unwrap();
        assert_eq!(&skin[..20], node_id);
        assert_eq!(&skin[20..52], &b_pub);
        let mut x_pub = [0u8; 32];
        x_pub.copy_from_slice(&skin[52..84]);

        let ephemeral = EphemeralSecret::generate().unwrap();
        let y_pub = ephemeral.public_key().unwrap();

        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(&ephemeral.diffie_hellman(&x_pub).unwrap());
        secret_input.extend_from_slice(&onion_secret.diffie_hellman(&x_pub).unwrap());
        secret_input.extend_from_slice(node_id);
        secret_input.extend_from_slice(&b_pub);
        secret_input.extend_from_slice(&x_pub);
        secret_input.extend_from_slice(&y_pub);
        secret_input.extend_from_slice(PROTOID);

        let key_seed = hmac_sha256(T_KEY, &secret_input);
        let verify = hmac_sha256(T_VERIFY, &secret_input);

        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(node_id);
        auth_input.extend_from_slice(&b_pub);
        auth_input.extend_from_slice(&y_pub);
        auth_input.extend_from_slice(&x_pub);
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(SERVER_STRING);

        let mut reply = Vec::new();
        reply.extend_from_slice(&y_pub);
        reply.extend_from_slice(&hmac_sha256(T_MAC, &auth_input));
        (reply, derive_keys(&key_seed))
    }

    #[test]
    fn client_and_server_agree() {
        let onion_secret = EphemeralSecret::generate().unwrap();
        let onion_key = onion_secret.public_key().unwrap();
        let node_id = [0x5au8; 20];

        let (client, skin) = NtorClient::new(&node_id, &onion_key).unwrap();
        assert_eq!(skin.len(), CLIENT_HANDSHAKE_LEN);

        let (reply, server_keys) = server_reply(&onion_secret, &node_id, &skin);
        assert_eq!(reply.len(), SERVER_HANDSHAKE_LEN);
        let client_keys = client.finish(&reply).unwrap();

        assert_eq!(client_keys.df, server_keys.df);
        assert_eq!(client_keys.db, server_keys.db);
        assert_eq!(client_keys.kf, server_keys.kf);
        assert_eq!(client_keys.kb, server_keys.kb);
        // The four pieces must be distinct slices of the keystream.
        assert_ne!(client_keys.df, client_keys.db);
        assert_ne!(client_keys.kf, client_keys.kb);
    }

    #[test]
    fn rejects_a_forged_auth() {
        let onion_secret = EphemeralSecret::generate().unwrap();
        let onion_key = onion_secret.public_key().unwrap();
        let node_id = [1u8; 20];
        let (client, skin) = NtorClient::new(&node_id, &onion_key).unwrap();
        let (mut reply, _) = server_reply(&onion_secret, &node_id, &skin);
        reply[40] ^= 0x01;
        assert!(client.finish(&reply).is_err());
        assert!(client.finish(&reply[..10]).is_err());
    }

    /// A relay that does not hold the private onion key cannot produce a
    /// reply the client will accept.
    #[test]
    fn rejects_a_relay_without_the_onion_key() {
        let real = EphemeralSecret::generate().unwrap();
        let node_id = [2u8; 20];
        let (client, skin) = NtorClient::new(&node_id, &real.public_key().unwrap()).unwrap();

        let impostor = EphemeralSecret::generate().unwrap();
        // The impostor answers using its own key, but the client's
        // secret_input still uses the advertised onion key.
        let mut forged_skin = skin.clone();
        forged_skin[20..52].copy_from_slice(&impostor.public_key().unwrap());
        let (reply, _) = server_reply(&impostor, &node_id, &forged_skin);
        assert!(client.finish(&reply).is_err());
    }

    /// The relay recomputes the same keystream from X|Y, so a client that
    /// gets the right KH back has the right Df/Db/Kf/Kb too.
    #[test]
    fn create_fast_round_trip() {
        let (client, x) = CreateFastClient::new().unwrap();
        assert_eq!(x.len(), CREATE_FAST_LEN);
        let y = [0x5cu8; CREATE_FAST_LEN];

        let mut k0 = x.clone();
        k0.extend_from_slice(&y);
        let stream = kdf_tor(&k0, 92);

        let mut reply = y.to_vec();
        reply.extend_from_slice(&stream[..20]);
        let keys = client.finish(&reply).unwrap();
        assert_eq!(&keys.df[..], &stream[20..40]);
        assert_eq!(&keys.db[..], &stream[40..60]);
        assert_eq!(&keys.kf[..], &stream[60..76]);
        assert_eq!(&keys.kb[..], &stream[76..92]);

        // A relay that derived something else fails the KH check.
        let mut bad = reply.clone();
        bad[25] ^= 1;
        assert!(client.finish(&bad).is_err());
        assert!(client.finish(&reply[..30]).is_err());
    }

    #[test]
    fn kdf_tor_matches_the_definition() {
        let k0 = b"key material";
        let out = kdf_tor(k0, 45);
        let mut expected = Vec::new();
        for counter in 0..3u8 {
            expected.extend_from_slice(&sha1(&[&k0[..], &[counter]].concat()));
        }
        assert_eq!(out, expected[..45]);
    }

    #[test]
    fn kdf_matches_the_recurrence() {
        let seed = [7u8; 32];
        let out = kdf_rfc5869(&seed, M_EXPAND, 72);
        let mut expected = Vec::new();
        let k1 = hmac_sha256(&seed, &[M_EXPAND, &[1]].concat());
        expected.extend_from_slice(&k1);
        let k2 = hmac_sha256(&seed, &[&k1[..], M_EXPAND, &[2]].concat());
        expected.extend_from_slice(&k2);
        let k3 = hmac_sha256(&seed, &[&k2[..], M_EXPAND, &[3]].concat());
        expected.extend_from_slice(&k3);
        assert_eq!(out, expected[..72]);
    }
}
