//! hs-ntor: the introduction and rendezvous handshake
//! (rend-spec/introduction-protocol.md, [NTOR-WITH-EXTRA-DATA]).
//!
//! Structurally this is the ntor handshake of tor-spec, with three changes:
//! SHA3-256 and SHAKE-256 replace SHA-256 and its KDF, the service's
//! introduction-point authentication key takes the place of a relay identity,
//! and the client's half runs in two stages. The first stage derives the keys
//! that encrypt the INTRODUCE1 message, which the introduction point forwards
//! blind; the second completes the handshake from the `Y | AUTH` the service
//! sends back through the rendezvous point.
//!
//! The keys it ends with are for a circuit hop, and are twice the size of an
//! ordinary hop's: AES-256 and SHA3-256 rather than AES-128 and SHA-1.

use std::io;

use super::mac;
use crate::ffi::constant_time_eq;
use crate::ffi::hash::shake256;
use crate::ffi::x25519::EphemeralSecret;
use crate::util::invalid_data;

const PROTOID: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1";
const T_HSENC: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract";
const T_HSVERIFY: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_verify";
const T_HSMAC: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_mac";
const M_HSEXPAND: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand";
const SERVER_STRING: &[u8] = b"Server";

/// The service's reply: `Y | AUTH`.
pub const SERVER_HANDSHAKE_LEN: usize = 32 + 32;

/// The keys that protect the encrypted part of an INTRODUCE1 message.
pub struct IntroduceKeys {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

/// Key material for the rendezvous circuit's virtual hop. Deliberately a
/// separate type from [`crate::tor::ntor::CircuitKeys`]: everything here is
/// 32 bytes, and mixing the two up would be a silent protocol failure.
pub struct HsCircuitKeys {
    pub df: [u8; 32],
    pub db: [u8; 32],
    pub kf: [u8; 32],
    pub kb: [u8; 32],
}

/// The client half of an hs-ntor handshake with one onion service.
pub struct HsNtorClient {
    secret: EphemeralSecret,
    x_pub: [u8; 32],
    auth_key: [u8; 32],
    /// `B`, the service's `KP_hss_ntor` from the descriptor's `enc-key`.
    enc_key: [u8; 32],
    /// `EXP(B, x)`, which both stages need.
    exp_bx: [u8; 32],
}

impl HsNtorClient {
    /// Start a handshake with the service reachable through the introduction
    /// point named by `auth_key`, whose encryption key is `enc_key`.
    pub fn new(auth_key: &[u8; 32], enc_key: &[u8; 32]) -> io::Result<Self> {
        let secret = EphemeralSecret::generate()?;
        Self::with_secret(secret, auth_key, enc_key)
    }

    fn with_secret(
        secret: EphemeralSecret,
        auth_key: &[u8; 32],
        enc_key: &[u8; 32],
    ) -> io::Result<Self> {
        let x_pub = secret.public_key()?;
        let exp_bx = secret.diffie_hellman(enc_key)?;
        Ok(Self {
            secret,
            x_pub,
            auth_key: *auth_key,
            enc_key: *enc_key,
            exp_bx,
        })
    }

    /// `X`, which travels in the clear at the front of the ENCRYPTED section.
    pub fn client_public(&self) -> [u8; 32] {
        self.x_pub
    }

    /// The keys for the INTRODUCE1 message, which only this service can
    /// derive: they depend on `EXP(B, x)` and on the subcredential.
    pub fn introduce_keys(&self, subcredential: &[u8; 32]) -> IntroduceKeys {
        let mut input =
            Vec::with_capacity(32 * 4 + PROTOID.len() + T_HSENC.len() + M_HSEXPAND.len() + 32);
        input.extend_from_slice(&self.exp_bx);
        input.extend_from_slice(&self.auth_key);
        input.extend_from_slice(&self.x_pub);
        input.extend_from_slice(&self.enc_key);
        input.extend_from_slice(PROTOID);
        input.extend_from_slice(T_HSENC);
        // info = m_hsexpand | N_hs_subcred
        input.extend_from_slice(M_HSEXPAND);
        input.extend_from_slice(subcredential);

        let keys = shake256(&input, 64);
        IntroduceKeys {
            enc_key: keys[..32].try_into().unwrap(),
            mac_key: keys[32..].try_into().unwrap(),
        }
    }

    /// Check the service's `Y | AUTH` and derive the virtual hop's keys.
    pub fn finish(&self, reply: &[u8]) -> io::Result<HsCircuitKeys> {
        if reply.len() < SERVER_HANDSHAKE_LEN {
            return Err(invalid_data("hs-ntor reply is too short"));
        }
        let y_pub: [u8; 32] = reply[..32].try_into().unwrap();
        let auth = &reply[32..64];

        // OpenSSL refuses an all-zero shared secret, which is the low-order
        // point check this handshake relies on.
        let exp_yx = self.secret.diffie_hellman(&y_pub)?;

        let mut rend_secret = Vec::with_capacity(32 * 6 + PROTOID.len());
        rend_secret.extend_from_slice(&exp_yx);
        rend_secret.extend_from_slice(&self.exp_bx);
        rend_secret.extend_from_slice(&self.auth_key);
        rend_secret.extend_from_slice(&self.enc_key);
        rend_secret.extend_from_slice(&self.x_pub);
        rend_secret.extend_from_slice(&y_pub);
        rend_secret.extend_from_slice(PROTOID);

        // Here the *first* argument is the MAC key, matching C Tor's
        // crypto_mac_sha3_256(out, key, msg).
        let key_seed = mac(&rend_secret, T_HSENC);
        let verify = mac(&rend_secret, T_HSVERIFY);

        let mut auth_input = Vec::with_capacity(32 * 5 + PROTOID.len() + SERVER_STRING.len());
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(&self.auth_key);
        auth_input.extend_from_slice(&self.enc_key);
        auth_input.extend_from_slice(&y_pub);
        auth_input.extend_from_slice(&self.x_pub);
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(SERVER_STRING);

        if !constant_time_eq(&mac(&auth_input, T_HSMAC), auth) {
            return Err(invalid_data(
                "hs-ntor AUTH mismatch: the far end is not the onion service we asked for",
            ));
        }

        Ok(derive_keys(&key_seed))
    }
}

/// `K = SHAKE256(NTOR_KEY_SEED | m_hsexpand, 128)`, split into the four
/// per-direction pieces the virtual hop needs.
fn derive_keys(key_seed: &[u8; 32]) -> HsCircuitKeys {
    let mut input = Vec::with_capacity(32 + M_HSEXPAND.len());
    input.extend_from_slice(key_seed);
    input.extend_from_slice(M_HSEXPAND);
    let stream = shake256(&input, 128);
    HsCircuitKeys {
        df: stream[0..32].try_into().unwrap(),
        db: stream[32..64].try_into().unwrap(),
        kf: stream[64..96].try_into().unwrap(),
        kb: stream[96..128].try_into().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    fn key(hex: &str) -> [u8; 32] {
        hex_decode(hex).unwrap().try_into().unwrap()
    }

    /// rend-spec appendix G.1: a complete handshake captured from C Tor.
    ///
    /// Everything the client computes is pinned here -- the INTRODUCE1 keys
    /// from the first stage and both halves of the second.
    #[test]
    fn rend_spec_test_vectors() {
        let auth_key = key("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F");
        let b_pub = key("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979");
        let subcredential = key("0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57");
        let x = key("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341");
        let x_pub = key("BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D");

        let client = HsNtorClient::with_secret(
            EphemeralSecret::from_raw_private(&x).unwrap(),
            &auth_key,
            &b_pub,
        )
        .unwrap();
        assert_eq!(client.client_public(), x_pub);

        let keys = client.introduce_keys(&subcredential);
        assert_eq!(
            keys.enc_key,
            key("9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706")
        );
        assert_eq!(
            keys.mac_key,
            key("FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5")
        );

        let y_pub = key("8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700");
        let auth = key("4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208");
        let mut reply = y_pub.to_vec();
        reply.extend_from_slice(&auth);
        let circuit_keys = client.finish(&reply).expect("the vector must verify");

        // The seed itself is not returned, so check it through the keys it
        // expands to.
        let seed = key("4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB");
        let expected = derive_keys(&seed);
        assert_eq!(circuit_keys.df, expected.df);
        assert_eq!(circuit_keys.db, expected.db);
        assert_eq!(circuit_keys.kf, expected.kf);
        assert_eq!(circuit_keys.kb, expected.kb);
        // The four pieces are distinct slices of one keystream.
        assert_ne!(circuit_keys.df, circuit_keys.db);
        assert_ne!(circuit_keys.kf, circuit_keys.kb);
    }

    #[test]
    fn rejects_a_forged_or_truncated_reply() {
        let auth_key = key("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F");
        let b_pub = key("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979");
        let x = key("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341");
        let client = HsNtorClient::with_secret(
            EphemeralSecret::from_raw_private(&x).unwrap(),
            &auth_key,
            &b_pub,
        )
        .unwrap();

        let mut reply =
            key("8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700").to_vec();
        reply.extend_from_slice(&key(
            "4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208",
        ));
        assert!(client.finish(&reply).is_ok());

        let mut forged = reply.clone();
        forged[40] ^= 1;
        assert!(client.finish(&forged).is_err());
        // A different Y makes AUTH wrong too, which is the point.
        let mut other_y = reply.clone();
        other_y[0] ^= 1;
        assert!(client.finish(&other_y).is_err());
        assert!(client.finish(&reply[..63]).is_err());
    }

    /// The subcredential is what ties the introduction keys to one time
    /// period, so it has to reach the KDF.
    #[test]
    fn introduce_keys_depend_on_the_subcredential() {
        let client = HsNtorClient::new(&[1u8; 32], &[2u8; 32]).unwrap();
        let a = client.introduce_keys(&[3u8; 32]);
        let b = client.introduce_keys(&[4u8; 32]);
        assert_ne!(a.enc_key, b.enc_key);
        assert_ne!(a.mac_key, b.mac_key);
        assert_ne!(a.enc_key, a.mac_key);
    }

    /// A service that does not hold `b` cannot produce a reply the client
    /// accepts, however well-formed it looks.
    #[test]
    fn an_impostor_cannot_complete_the_handshake() {
        let real = EphemeralSecret::generate().unwrap();
        let auth_key = [0x5au8; 32];
        let client = HsNtorClient::new(&auth_key, &real.public_key().unwrap()).unwrap();

        let impostor = EphemeralSecret::generate().unwrap();
        let ephemeral = EphemeralSecret::generate().unwrap();
        let y_pub = ephemeral.public_key().unwrap();
        let x_pub = client.client_public();

        // The service side of the formula, but with the wrong long-term key.
        let mut rend_secret = Vec::new();
        rend_secret.extend_from_slice(&ephemeral.diffie_hellman(&x_pub).unwrap());
        rend_secret.extend_from_slice(&impostor.diffie_hellman(&x_pub).unwrap());
        rend_secret.extend_from_slice(&auth_key);
        rend_secret.extend_from_slice(&real.public_key().unwrap());
        rend_secret.extend_from_slice(&x_pub);
        rend_secret.extend_from_slice(&y_pub);
        rend_secret.extend_from_slice(PROTOID);

        let verify = mac(&rend_secret, T_HSVERIFY);
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(&auth_key);
        auth_input.extend_from_slice(&real.public_key().unwrap());
        auth_input.extend_from_slice(&y_pub);
        auth_input.extend_from_slice(&x_pub);
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(SERVER_STRING);

        let mut reply = y_pub.to_vec();
        reply.extend_from_slice(&mac(&auth_input, T_HSMAC));
        assert!(client.finish(&reply).is_err());
    }
}
