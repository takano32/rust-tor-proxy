//! ntor-v3: the circuit handshake that carries extra data
//! (tor-spec/create-created-cells.md "The ntor-v3 handshake", proposal 332).
//!
//! This is the ntor handshake of `super::ntor` with three changes. SHA3-256
//! and SHAKE-256 replace SHA-256 and HMAC; the relay is named by its Ed25519
//! identity rather than by the SHA-1 of its RSA key, so `ID` is 32 bytes and
//! not 20; and each side may attach an encrypted message to its half of the
//! handshake. The client's message is encrypted under a key derived from
//! `EXP(B, x)` alone, so it has no forward secrecy; the relay's is encrypted
//! under the final key seed, so it does.
//!
//! Those messages are the extension lists of
//! tor-spec/create-created-cells.md#additional-data, which is how a circuit
//! negotiates congestion control and subprotocol features at creation time.
//!
//! What comes out is an ordinary tor1 hop: the keystream is partitioned into
//! `Df | Db | Kf | Kb` exactly as ntor's is, so this yields the same
//! [`CircuitKeys`] the rest of the circuit code already knows.

use std::io;

use crate::ffi::aes::Aes256Ctr;
use crate::ffi::constant_time_eq;
use crate::ffi::hash::{sha3_256, shake256};
use crate::ffi::x25519::EphemeralSecret;
use crate::tor::ntor::CircuitKeys;
use crate::util::invalid_data;

/// HTYPE for ntor-v3 in CREATE2 / EXTEND2. Relays advertise it as `Relay=4`.
pub const HANDSHAKE_TYPE_NTOR_V3: u16 = 0x0003;

/// `PROTOID`, and the six tweak strings built from it. Each tweak keeps one
/// use of SHA3-256/SHAKE-256 from colliding with another, so they are written
/// out in full rather than concatenated at run time: a typo in one of them
/// produces keys that differ from the relay's with no other symptom.
const PROTOID: &[u8] = b"ntor3-curve25519-sha3_256-1";
const T_MSGKDF: &[u8] = b"ntor3-curve25519-sha3_256-1:kdf_phase1";
const T_MSGMAC: &[u8] = b"ntor3-curve25519-sha3_256-1:msg_mac";
const T_KEY_SEED: &[u8] = b"ntor3-curve25519-sha3_256-1:key_seed";
const T_VERIFY: &[u8] = b"ntor3-curve25519-sha3_256-1:verify";
const T_FINAL: &[u8] = b"ntor3-curve25519-sha3_256-1:kdf_final";
const T_AUTH: &[u8] = b"ntor3-curve25519-sha3_256-1:auth_final";
const SERVER_STRING: &[u8] = b"Server";

/// `VER`, the verification string both sides mix into `secret_input`. The
/// handshake is generic over it; the value for circuit extension is not in
/// tor-spec, only in the implementations, where C Tor and arti both use
/// `"circuit extend"` (arti's `NTOR3_CIRC_VERIFICATION`). Getting it wrong
/// fails every handshake against the live network and nothing else.
const CIRC_VERIFICATION: &[u8] = b"circuit extend";

/// `Y | AUTH`, before the relay's (possibly empty) encrypted message.
const SERVER_REPLY_PREFIX_LEN: usize = 32 + 32;

/// `Df(20) | Db(20) | Kf(16) | Kb(16)`, the tor1 relay-crypto material, taken
/// from the keystream that follows `ENC_KEY`. tor-spec/setting-circuit-keys.md
/// notes that ntor-v3 partitions its keystream just as ntor does.
const CIRCUIT_KEY_LEN: usize = 20 + 20 + 16 + 16;

/// One extension field: `TYPE(1) | LEN(1) | BODY`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub kind: u8,
    pub body: Vec<u8>,
}

/// `N_EXTENSIONS(1)` followed by that many `TYPE | LEN | BODY` fields
/// (tor-spec/create-created-cells.md#additional-data).
pub fn encode_extensions(exts: &[Extension]) -> io::Result<Vec<u8>> {
    if exts.len() > u8::MAX as usize {
        return Err(invalid_data("too many handshake extensions for one byte"));
    }
    let mut out = Vec::with_capacity(1 + exts.len() * 2);
    out.push(exts.len() as u8);
    for ext in exts {
        if ext.body.len() > u8::MAX as usize {
            return Err(invalid_data("handshake extension body is over 255 bytes"));
        }
        out.push(ext.kind);
        out.push(ext.body.len() as u8);
        out.extend_from_slice(&ext.body);
    }
    Ok(out)
}

/// The inverse. The spec says parties "MUST reject messages that are not
/// well-formed", so a short field, a missing count and trailing bytes past the
/// last field are all errors rather than something to skip over. Unknown
/// `TYPE`s are *not* an error -- they are returned for the caller to ignore.
pub fn decode_extensions(data: &[u8]) -> io::Result<Vec<Extension>> {
    let (&count, mut rest) = data
        .split_first()
        .ok_or_else(|| invalid_data("handshake extension list is empty"))?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if rest.len() < 2 {
            return Err(invalid_data("truncated handshake extension header"));
        }
        let len = rest[1] as usize;
        if rest.len() < 2 + len {
            return Err(invalid_data("truncated handshake extension body"));
        }
        out.push(Extension {
            kind: rest[0],
            body: rest[2..2 + len].to_vec(),
        });
        rest = &rest[2 + len..];
    }
    if !rest.is_empty() {
        return Err(invalid_data(
            "trailing bytes after the handshake extensions",
        ));
    }
    Ok(out)
}

/// Client state between sending the onion skin and receiving the reply.
pub struct NtorV3Client {
    secret: EphemeralSecret,
    /// `X`.
    x_pub: [u8; 32],
    /// `ID`, the relay's Ed25519 identity.
    id: [u8; 32],
    /// `B`, the relay's `KP_onion_ntor`.
    b_pub: [u8; 32],
    /// `EXP(B, x)`, which both phases need.
    exp_bx: [u8; 32],
    /// `msg_mac`, which the relay feeds back into `auth_input`: that is what
    /// binds its reply to this particular client message.
    msg_mac: [u8; 32],
    /// `VER`.
    verification: Vec<u8>,
}

impl NtorV3Client {
    /// Start a handshake with the relay whose Ed25519 identity is `id` and
    /// whose ntor onion key is `b`, carrying `extensions` in the client
    /// message. Returns the client state and the HDATA to put in
    /// CREATE2 / EXTEND2.
    pub fn new(
        id: &[u8; 32],
        b: &[u8; 32],
        extensions: &[Extension],
    ) -> io::Result<(Self, Vec<u8>)> {
        let message = encode_extensions(extensions)?;
        Self::build(
            EphemeralSecret::generate()?,
            id,
            b,
            &message,
            CIRC_VERIFICATION,
        )
    }

    /// The handshake proper, with `CM` and `VER` supplied rather than implied.
    /// Only the tests need that freedom, but the code path must be the shared
    /// one or the vectors would prove nothing about [`NtorV3Client::new`].
    fn build(
        secret: EphemeralSecret,
        id: &[u8; 32],
        b: &[u8; 32],
        message: &[u8],
        verification: &[u8],
    ) -> io::Result<(Self, Vec<u8>)> {
        let x_pub = secret.public_key()?;
        // OpenSSL refuses an all-zero shared secret, which is the
        // small-subgroup check proposal 332 asks implementations to make.
        let exp_bx = secret.diffie_hellman(b)?;

        // secret_input_phase1 = Bx | ID | X | B | PROTOID | ENCAP(VER)
        let mut phase1_input = Vec::with_capacity(32 * 4 + PROTOID.len() + 8 + verification.len());
        phase1_input.extend_from_slice(&exp_bx);
        phase1_input.extend_from_slice(id);
        phase1_input.extend_from_slice(&x_pub);
        phase1_input.extend_from_slice(b);
        phase1_input.extend_from_slice(PROTOID);
        encap_into(&mut phase1_input, verification);

        // (ENC_K1, MAC_K1) = PARTITION(KDF_msgkdf(secret_input_phase1), 32, 32)
        let phase1_keys = kdf(&phase1_input, T_MSGKDF, 64);
        let enc_k1: [u8; 32] = phase1_keys[..32].try_into().unwrap();
        let mac_k1 = &phase1_keys[32..64];

        // The onion skin is ID | B | X | encrypted_msg | msg_mac, and the MAC
        // covers exactly the part of it built so far -- ID | B | X |
        // encrypted_msg -- so it is computed over the buffer in place.
        let mut hdata = Vec::with_capacity(32 * 4 + message.len());
        hdata.extend_from_slice(id);
        hdata.extend_from_slice(b);
        hdata.extend_from_slice(&x_pub);
        hdata.extend_from_slice(&enc(&enc_k1, message));
        let msg_mac = mac(mac_k1, &hdata, T_MSGMAC);
        hdata.extend_from_slice(&msg_mac);

        Ok((
            Self {
                secret,
                x_pub,
                id: *id,
                b_pub: *b,
                exp_bx,
                msg_mac,
                verification: verification.to_vec(),
            },
            hdata,
        ))
    }

    /// Check the relay's reply and derive the circuit keys, returning also
    /// whatever extensions the relay sent back.
    pub fn finish(&self, reply: &[u8]) -> io::Result<(CircuitKeys, Vec<Extension>)> {
        let (keystream, server_message) = self.complete(reply, CIRCUIT_KEY_LEN)?;
        let keys = CircuitKeys {
            df: keystream[0..20].try_into().unwrap(),
            db: keystream[20..40].try_into().unwrap(),
            kf: keystream[40..56].try_into().unwrap(),
            kb: keystream[56..72].try_into().unwrap(),
        };
        Ok((keys, decode_extensions(&server_message)?))
    }

    /// Phase two: authenticate `Y | AUTH | encrypted_msg` and return
    /// `keystream_len` bytes of KEYSTREAM together with the decrypted `SM`.
    ///
    /// The length is a parameter only so the test vectors can ask for the 256
    /// bytes proposal 332 publishes; [`NtorV3Client::finish`] asks for the 72
    /// a tor1 hop consumes.
    fn complete(&self, reply: &[u8], keystream_len: usize) -> io::Result<(Vec<u8>, Vec<u8>)> {
        if reply.len() < SERVER_REPLY_PREFIX_LEN {
            return Err(invalid_data("ntor-v3 reply is too short"));
        }
        let y_pub: [u8; 32] = reply[..32].try_into().unwrap();
        let auth = &reply[32..64];
        let encrypted_reply = &reply[64..];

        let exp_yx = self.secret.diffie_hellman(&y_pub)?;

        // secret_input = Yx | Bx | ID | B | X | Y | PROTOID | ENCAP(VER)
        //
        // Note the order: the two curve25519 outputs lead, and unlike the
        // phase-1 input this one carries B *before* X.
        let mut secret_input =
            Vec::with_capacity(32 * 6 + PROTOID.len() + 8 + self.verification.len());
        secret_input.extend_from_slice(&exp_yx);
        secret_input.extend_from_slice(&self.exp_bx);
        secret_input.extend_from_slice(&self.id);
        secret_input.extend_from_slice(&self.b_pub);
        secret_input.extend_from_slice(&self.x_pub);
        secret_input.extend_from_slice(&y_pub);
        secret_input.extend_from_slice(PROTOID);
        encap_into(&mut secret_input, &self.verification);

        let key_seed = h(&secret_input, T_KEY_SEED);
        let verify = h(&secret_input, T_VERIFY);

        // auth_input = verify | ID | B | Y | X | MAC | ENCAP(MSG) |
        //              PROTOID | "Server"
        //
        // `MAC` here is the client's own msg_mac and `MSG` the relay's
        // encrypted reply, which is length-prefixed because it is the only
        // variable-length field: without ENCAP() a relay could shift bytes
        // between it and PROTOID.
        let mut auth_input = Vec::with_capacity(
            32 * 6 + 8 + encrypted_reply.len() + PROTOID.len() + SERVER_STRING.len(),
        );
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(&self.id);
        auth_input.extend_from_slice(&self.b_pub);
        auth_input.extend_from_slice(&y_pub);
        auth_input.extend_from_slice(&self.x_pub);
        auth_input.extend_from_slice(&self.msg_mac);
        encap_into(&mut auth_input, encrypted_reply);
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(SERVER_STRING);

        if !constant_time_eq(&h(&auth_input, T_AUTH), auth) {
            return Err(invalid_data(
                "ntor-v3 AUTH mismatch: relay did not prove its onion key",
            ));
        }

        // RAW_KEYSTREAM = KDF_final(ntor_key_seed), whose first 32 bytes are
        // the key for the relay's message and whose remainder is the circuit
        // keystream.
        let raw = kdf(&key_seed, T_FINAL, 32 + keystream_len);
        let enc_key: [u8; 32] = raw[..32].try_into().unwrap();
        let server_message = enc(&enc_key, encrypted_reply);
        Ok((raw[32..].to_vec(), server_message))
    }
}

#[cfg(test)]
impl NtorV3Client {
    /// Run the handshake with a fixed `x`, `CM` and `VER`, for test vectors.
    fn with_secret(
        secret: EphemeralSecret,
        id: &[u8; 32],
        b: &[u8; 32],
        message: &[u8],
        verification: &[u8],
    ) -> io::Result<(Self, Vec<u8>)> {
        Self::build(secret, id, b, message, verification)
    }
}

/// `ENCAP(s) = INT_8(len(s)) | s`, where `INT_8` is eight bytes big-endian
/// (proposal 332 writes it `htonll(len(s)) | s`).
fn encap_into(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u64).to_be_bytes());
    out.extend_from_slice(s);
}

/// `H(s, t) = SHA3_256(ENCAP(t) | s)`.
fn h(s: &[u8], t: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + t.len() + s.len());
    encap_into(&mut input, t);
    input.extend_from_slice(s);
    sha3_256(&input)
}

/// `MAC(k, msg, t) = SHA3_256(ENCAP(t) | ENCAP(k) | msg)`.
///
/// Both the tweak and the key are encapsulated, but the message is not: it is
/// last, so nothing can be shifted into it.
fn mac(k: &[u8], msg: &[u8], t: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(16 + t.len() + k.len() + msg.len());
    encap_into(&mut input, t);
    encap_into(&mut input, k);
    input.extend_from_slice(msg);
    sha3_256(&input)
}

/// `KDF(s, t) = SHAKE_256(ENCAP(t) | s)`, truncated to `out_len`.
///
/// SHAKE-256 is an XOF, so a longer request extends the same stream: taking
/// `n + m` bytes and splitting them is identical to taking `n` and then `m`,
/// which is what the spec's `PARTITION()` means.
fn kdf(s: &[u8], t: &[u8], out_len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(8 + t.len() + s.len());
    encap_into(&mut input, t);
    input.extend_from_slice(s);
    shake256(&input, out_len)
}

/// `ENC(k, m) = AES_256_CTR(k, m)` with an all-zero IV; `DEC` is the same
/// operation. Each key is used for exactly one message, so the fixed counter
/// is safe here and nowhere else.
fn enc(key: &[u8; 32], m: &[u8]) -> Vec<u8> {
    let mut out = m.to_vec();
    Aes256Ctr::new(key).apply(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    fn bytes(hex: &str) -> Vec<u8> {
        hex_decode(hex).unwrap()
    }

    fn key(hex: &str) -> [u8; 32] {
        bytes(hex).try_into().unwrap()
    }

    /// The relay's half of the handshake, from
    /// tor-spec/create-created-cells.md#ntor-v3. Written out here for the same
    /// reason `super::ntor`'s tests write out ntor's: a wrong concatenation
    /// order is invisible until it meets a real relay, and a server built from
    /// the same spec text is the only offline check of it.
    ///
    /// Returns the CREATED2 HDATA, the relay's circuit keys and the client's
    /// extensions as the relay decrypted them.
    fn server_reply(
        b_secret: &EphemeralSecret,
        y_secret: &EphemeralSecret,
        id: &[u8; 32],
        verification: &[u8],
        hdata: &[u8],
        server_message: &[u8],
    ) -> io::Result<(Vec<u8>, CircuitKeys, Vec<u8>)> {
        let b_pub = b_secret.public_key()?;
        assert!(hdata.len() >= 32 * 4);
        assert_eq!(&hdata[..32], id, "NODEID is not this relay");
        assert_eq!(&hdata[32..64], &b_pub, "KEYID is not this relay's key");
        let x_pub: [u8; 32] = hdata[64..96].try_into().unwrap();
        let encrypted_msg = &hdata[96..hdata.len() - 32];
        let msg_mac = &hdata[hdata.len() - 32..];

        // secret_input_phase1 = Xb | ID | X | B | PROTOID | ENCAP(VER)
        let xb = b_secret.diffie_hellman(&x_pub)?;
        let mut phase1_input = Vec::new();
        phase1_input.extend_from_slice(&xb);
        phase1_input.extend_from_slice(id);
        phase1_input.extend_from_slice(&x_pub);
        phase1_input.extend_from_slice(&b_pub);
        phase1_input.extend_from_slice(PROTOID);
        encap_into(&mut phase1_input, verification);

        let phase1_keys = kdf(&phase1_input, T_MSGKDF, 64);
        let enc_k1: [u8; 32] = phase1_keys[..32].try_into().unwrap();
        let expected_mac = mac(&phase1_keys[32..64], &hdata[..hdata.len() - 32], T_MSGMAC);
        if !constant_time_eq(&expected_mac, msg_mac) {
            // A real relay drops the circuit here. It is also where a VER
            // mismatch surfaces, since VER is inside secret_input_phase1.
            return Err(invalid_data("client msg_mac did not verify"));
        }
        let client_message = enc(&enc_k1, encrypted_msg);

        // secret_input = Xy | Xb | ID | B | X | Y | PROTOID | ENCAP(VER)
        let y_pub = y_secret.public_key()?;
        let xy = y_secret.diffie_hellman(&x_pub)?;
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(&xy);
        secret_input.extend_from_slice(&xb);
        secret_input.extend_from_slice(id);
        secret_input.extend_from_slice(&b_pub);
        secret_input.extend_from_slice(&x_pub);
        secret_input.extend_from_slice(&y_pub);
        secret_input.extend_from_slice(PROTOID);
        encap_into(&mut secret_input, verification);

        let key_seed = h(&secret_input, T_KEY_SEED);
        let verify = h(&secret_input, T_VERIFY);

        let raw = kdf(&key_seed, T_FINAL, 32 + CIRCUIT_KEY_LEN);
        let enc_key: [u8; 32] = raw[..32].try_into().unwrap();
        let encrypted_reply = enc(&enc_key, server_message);

        // auth_input = verify | ID | B | Y | X | MAC | ENCAP(MSG) |
        //              PROTOID | "Server"
        let mut auth_input = Vec::new();
        auth_input.extend_from_slice(&verify);
        auth_input.extend_from_slice(id);
        auth_input.extend_from_slice(&b_pub);
        auth_input.extend_from_slice(&y_pub);
        auth_input.extend_from_slice(&x_pub);
        auth_input.extend_from_slice(msg_mac);
        encap_into(&mut auth_input, &encrypted_reply);
        auth_input.extend_from_slice(PROTOID);
        auth_input.extend_from_slice(SERVER_STRING);

        let mut reply = Vec::new();
        reply.extend_from_slice(&y_pub);
        reply.extend_from_slice(&h(&auth_input, T_AUTH));
        reply.extend_from_slice(&encrypted_reply);

        let keys = CircuitKeys {
            df: raw[32..52].try_into().unwrap(),
            db: raw[52..72].try_into().unwrap(),
            kf: raw[72..88].try_into().unwrap(),
            kb: raw[88..104].try_into().unwrap(),
        };
        Ok((reply, keys, client_message))
    }

    /// Proposal 332 appendix X.2, "generated by a Python reference
    /// implementation" and pinned identically in arti's
    /// `tor-proto/src/crypto/handshake/ntor_v3.rs::test_ntor3_testvec`.
    ///
    /// `CM` and `SM` here are "hello world" and "Hola Mundo", not extension
    /// lists, and `VER` is the five bytes "xyzzy" rather than the string used
    /// for circuit extension -- which is why the raw `build`/`complete` pair
    /// is exercised rather than `new`/`finish`.
    #[test]
    fn proposal_332_test_vectors() {
        let b = key("4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a");
        let b_pub = key("f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d");
        let id = key("9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2");
        let x = key("b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49");
        let x_pub = key("252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f46");
        let y = key("4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053");
        let y_pub = key("4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d");
        let cm = bytes("68656c6c6f20776f726c64");
        let ver = bytes("78797a7a79");
        let sm = bytes("486f6c61204d756e646f");

        let b_secret = EphemeralSecret::from_raw_private(&b).unwrap();
        assert_eq!(b_secret.public_key().unwrap(), b_pub);
        let y_secret = EphemeralSecret::from_raw_private(&y).unwrap();
        assert_eq!(y_secret.public_key().unwrap(), y_pub);

        let (client, hdata) = NtorV3Client::with_secret(
            EphemeralSecret::from_raw_private(&x).unwrap(),
            &id,
            &b_pub,
            &cm,
            &ver,
        )
        .unwrap();
        assert_eq!(client.x_pub, x_pub);
        assert_eq!(
            hdata,
            bytes(concat!(
                "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2",
                "f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d",
                "252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f46",
                "3bebd9151fd3b47c180abc",
                "9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67",
            ))
        );

        // The published intermediate values, recomputed from the same helpers
        // the client uses: a wrong tweak or a wrong ENCAP() shows up here
        // rather than several stages later.
        let bx = EphemeralSecret::from_raw_private(&x)
            .unwrap()
            .diffie_hellman(&b_pub)
            .unwrap();
        let mut phase1_input = Vec::new();
        phase1_input.extend_from_slice(&bx);
        phase1_input.extend_from_slice(&id);
        phase1_input.extend_from_slice(&x_pub);
        phase1_input.extend_from_slice(&b_pub);
        phase1_input.extend_from_slice(PROTOID);
        encap_into(&mut phase1_input, &ver);
        let phase1_keys = kdf(&phase1_input, T_MSGKDF, 64);
        assert_eq!(
            phase1_keys[..32],
            bytes("4cd166e93f1c60a29f8fb9ec40ea0fc878930c27800594593e1c4d0f3b5fbd02")[..]
        );
        assert_eq!(
            phase1_keys[32..],
            bytes("f5b69e85fdd26e1b0bdbbc8128e32d8123040255f11f744af3cc98fc13613cda")[..]
        );
        assert_eq!(
            client.msg_mac,
            key("9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")
        );

        let yx = EphemeralSecret::from_raw_private(&x)
            .unwrap()
            .diffie_hellman(&y_pub)
            .unwrap();
        let mut secret_input = Vec::new();
        secret_input.extend_from_slice(&yx);
        secret_input.extend_from_slice(&bx);
        secret_input.extend_from_slice(&id);
        secret_input.extend_from_slice(&b_pub);
        secret_input.extend_from_slice(&x_pub);
        secret_input.extend_from_slice(&y_pub);
        secret_input.extend_from_slice(PROTOID);
        encap_into(&mut secret_input, &ver);
        let key_seed = h(&secret_input, T_KEY_SEED);
        assert_eq!(
            key_seed,
            key("b9a092741098e1f5b8ab37ce74399dd57522c974d7ae4626283a1077b9273255")
        );
        assert_eq!(
            h(&secret_input, T_VERIFY),
            key("1dc09fb249738a79f1bc3a545eee8c415f27213894a760bb4df58862e414799a")
        );
        assert_eq!(
            kdf(&key_seed, T_FINAL, 32)[..],
            bytes("cab8a93eef62246a83536c4384f331ec26061b66098c61421b6cae81f4f57c56")[..]
        );

        // The published server handshake, and the first 256 bytes of the
        // keystream that follows ENC_KEY.
        let server_handshake = bytes(concat!(
            "4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d",
            "2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a9127665",
            "1202c3e1e87c0d32054c",
        ));
        let (keystream, server_message) = client.complete(&server_handshake, 256).unwrap();
        assert_eq!(server_message, sm);
        assert_eq!(
            keystream,
            bytes(concat!(
                "9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3b",
                "feaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1",
                "b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bd",
                "e025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984c",
                "aa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b0",
                "9749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5",
                "618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f2",
                "26b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a",
            ))
        );

        // And the same reply built by the relay half below, which proves that
        // half against the vector too.
        let (reply, _, client_message) =
            server_reply(&b_secret, &y_secret, &id, &ver, &hdata, &sm).unwrap();
        assert_eq!(reply, server_handshake);
        assert_eq!(client_message, cm);
    }

    /// A full exchange with extensions in both directions: both sides must
    /// reach the same `Df | Db | Kf | Kb`.
    #[test]
    fn client_and_server_agree() {
        let b_secret = EphemeralSecret::generate().unwrap();
        let b_pub = b_secret.public_key().unwrap();
        let id = [0x5au8; 32];

        let client_exts = vec![
            Extension {
                kind: 1,
                body: vec![0x01, 0xf4],
            },
            Extension {
                kind: 3,
                body: Vec::new(),
            },
        ];
        let (client, hdata) = NtorV3Client::new(&id, &b_pub, &client_exts).unwrap();
        // ID | B | X | encrypted CM | msg_mac, where CM is the seven bytes
        // N_EXT(1) | 1,2,<2 bytes> | 3,0.
        assert_eq!(hdata.len(), 32 * 4 + 7);

        let server_exts = vec![Extension {
            kind: 2,
            body: vec![0x01, 0xf4],
        }];
        let (reply, server_keys, client_message) = server_reply(
            &b_secret,
            &EphemeralSecret::generate().unwrap(),
            &id,
            CIRC_VERIFICATION,
            &hdata,
            &encode_extensions(&server_exts).unwrap(),
        )
        .unwrap();
        assert_eq!(decode_extensions(&client_message).unwrap(), client_exts);

        let (client_keys, got_exts) = client.finish(&reply).unwrap();
        assert_eq!(got_exts, server_exts);
        assert_eq!(client_keys.df, server_keys.df);
        assert_eq!(client_keys.db, server_keys.db);
        assert_eq!(client_keys.kf, server_keys.kf);
        assert_eq!(client_keys.kb, server_keys.kb);
        // The four pieces must be distinct slices of the keystream.
        assert_ne!(client_keys.df, client_keys.db);
        assert_ne!(client_keys.kf, client_keys.kb);
    }

    /// An empty extension list is a one-byte message, and still has to travel
    /// and come back intact.
    #[test]
    fn round_trip_without_extensions() {
        let b_secret = EphemeralSecret::generate().unwrap();
        let b_pub = b_secret.public_key().unwrap();
        let id = [7u8; 32];
        let (client, hdata) = NtorV3Client::new(&id, &b_pub, &[]).unwrap();
        assert_eq!(hdata.len(), 32 * 4 + 1);

        let (reply, _, _) = server_reply(
            &b_secret,
            &EphemeralSecret::generate().unwrap(),
            &id,
            CIRC_VERIFICATION,
            &hdata,
            &[0u8],
        )
        .unwrap();
        assert_eq!(reply.len(), SERVER_REPLY_PREFIX_LEN + 1);
        let (_, exts) = client.finish(&reply).unwrap();
        assert!(exts.is_empty());
    }

    /// A relay that cannot compute `secret_input` cannot forge AUTH, and any
    /// tampering with `Y` or with AUTH itself must be caught.
    #[test]
    fn rejects_a_bad_reply() {
        let b_secret = EphemeralSecret::generate().unwrap();
        let b_pub = b_secret.public_key().unwrap();
        let id = [3u8; 32];
        let (client, hdata) = NtorV3Client::new(&id, &b_pub, &[]).unwrap();
        let (reply, _, _) = server_reply(
            &b_secret,
            &EphemeralSecret::generate().unwrap(),
            &id,
            CIRC_VERIFICATION,
            &hdata,
            &[0u8],
        )
        .unwrap();
        assert!(client.finish(&reply).is_ok());

        // A forged AUTH.
        let mut forged = reply.clone();
        forged[40] ^= 1;
        assert!(client.finish(&forged).is_err());

        // A different Y: AUTH no longer matches the secret_input it commits to.
        let mut other_y = reply.clone();
        other_y[1] ^= 1;
        assert!(client.finish(&other_y).is_err());

        // A truncated reply, both inside and at the edge of Y | AUTH.
        assert!(client.finish(&reply[..10]).is_err());
        assert!(client
            .finish(&reply[..SERVER_REPLY_PREFIX_LEN - 1])
            .is_err());

        // Tampering with the relay's encrypted message: ENCAP(MSG) is inside
        // auth_input, so this is caught before it is ever decrypted.
        let mut tampered = reply.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(client.finish(&tampered).is_err());
        assert!(client.finish(&reply[..reply.len() - 1]).is_err());
    }

    /// A relay that does not hold `b` cannot answer: it derives a different
    /// `Xb`, so its msg_mac check fails and its AUTH would not verify either.
    #[test]
    fn an_impostor_cannot_complete_the_handshake() {
        let real = EphemeralSecret::generate().unwrap();
        let impostor = EphemeralSecret::generate().unwrap();
        let id = [9u8; 32];
        let (client, hdata) = NtorV3Client::new(&id, &real.public_key().unwrap(), &[]).unwrap();

        // Let the impostor answer as if the onion skin had named its own key,
        // which is the most it can do.
        let mut forged_hdata = hdata.clone();
        forged_hdata[32..64].copy_from_slice(&impostor.public_key().unwrap());
        let y_secret = EphemeralSecret::generate().unwrap();
        let mut phase1_input = Vec::new();
        phase1_input.extend_from_slice(
            &impostor
                .diffie_hellman(&hdata[64..96].try_into().unwrap())
                .unwrap(),
        );
        phase1_input.extend_from_slice(&id);
        phase1_input.extend_from_slice(&hdata[64..96]);
        phase1_input.extend_from_slice(&impostor.public_key().unwrap());
        phase1_input.extend_from_slice(PROTOID);
        encap_into(&mut phase1_input, CIRC_VERIFICATION);
        let phase1_keys = kdf(&phase1_input, T_MSGKDF, 64);
        let new_mac = mac(
            &phase1_keys[32..64],
            &forged_hdata[..forged_hdata.len() - 32],
            T_MSGMAC,
        );
        let len = forged_hdata.len();
        forged_hdata[len - 32..].copy_from_slice(&new_mac);

        let (reply, _, _) = server_reply(
            &impostor,
            &y_secret,
            &id,
            CIRC_VERIFICATION,
            &forged_hdata,
            &[0u8],
        )
        .unwrap();
        assert!(client.finish(&reply).is_err());
    }

    /// VER is mixed into both `secret_input_phase1` and `secret_input`, so two
    /// sides that disagree about it fail rather than sharing keys. It fails at
    /// each end for its own reason: the relay cannot verify msg_mac, and a
    /// client that used a different VER cannot verify AUTH.
    #[test]
    fn a_mismatched_verification_string_fails() {
        let b_secret = EphemeralSecret::generate().unwrap();
        let b_pub = b_secret.public_key().unwrap();
        let id = [4u8; 32];
        let x = [0x11u8; 32];
        let cm = [0u8];

        let (client_a, hdata_a) = NtorV3Client::with_secret(
            EphemeralSecret::from_raw_private(&x).unwrap(),
            &id,
            &b_pub,
            &cm,
            b"verification A",
        )
        .unwrap();
        let (client_b, _) = NtorV3Client::with_secret(
            EphemeralSecret::from_raw_private(&x).unwrap(),
            &id,
            &b_pub,
            &cm,
            b"verification B",
        )
        .unwrap();

        // The relay refuses the onion skin outright under the wrong VER.
        assert!(server_reply(
            &b_secret,
            &EphemeralSecret::generate().unwrap(),
            &id,
            b"verification B",
            &hdata_a,
            &cm,
        )
        .is_err());

        // And a reply that is valid for VER "A" is not valid for VER "B",
        // even though both clients hold the same x.
        let (reply, _, _) = server_reply(
            &b_secret,
            &EphemeralSecret::generate().unwrap(),
            &id,
            b"verification A",
            &hdata_a,
            &cm,
        )
        .unwrap();
        assert!(client_a.finish(&reply).is_ok());
        assert!(client_b.finish(&reply).is_err());
    }

    #[test]
    fn extension_encoding_round_trip() {
        assert_eq!(encode_extensions(&[]).unwrap(), vec![0u8]);
        assert_eq!(decode_extensions(&[0u8]).unwrap(), Vec::new());

        let exts = vec![
            Extension {
                kind: 1,
                body: vec![0xaa, 0xbb],
            },
            Extension {
                kind: 200,
                body: Vec::new(),
            },
            Extension {
                kind: 3,
                body: vec![0xff; 255],
            },
        ];
        let encoded = encode_extensions(&exts).unwrap();
        assert_eq!(encoded[..4], [3, 1, 2, 0xaa]);
        assert_eq!(decode_extensions(&encoded).unwrap(), exts);
    }

    #[test]
    fn rejects_malformed_extensions() {
        // A body that does not fit in EXT_FIELD_LEN.
        assert!(encode_extensions(&[Extension {
            kind: 1,
            body: vec![0; 256],
        }])
        .is_err());

        // No N_EXTENSIONS byte at all.
        assert!(decode_extensions(&[]).is_err());
        // A field header cut short, and a body cut short.
        assert!(decode_extensions(&[1, 5]).is_err());
        assert!(decode_extensions(&[1, 5, 4, 0, 0, 0]).is_err());
        // More fields present than N_EXTENSIONS claims.
        assert!(decode_extensions(&[1, 5, 0, 6, 0]).is_err());
        // Trailing garbage after a well-formed list.
        assert!(decode_extensions(&[0, 0]).is_err());
        // The boundary case that must still work.
        assert_eq!(
            decode_extensions(&[1, 5, 0]).unwrap(),
            vec![Extension {
                kind: 5,
                body: Vec::new(),
            }]
        );
    }

    /// The tweak strings are what keep the six uses of SHA3-256/SHAKE-256
    /// apart, so a change of tweak must change the output.
    #[test]
    fn tweaks_separate_the_hashes() {
        assert_ne!(h(b"x", T_KEY_SEED), h(b"x", T_VERIFY));
        assert_ne!(h(b"x", T_KEY_SEED), h(b"x", T_AUTH));
        assert_ne!(kdf(b"x", T_MSGKDF, 32), kdf(b"x", T_FINAL, 32));
        assert_ne!(mac(b"k", b"m", T_MSGMAC), mac(b"k", b"m", T_AUTH));
        // ENCAP() of the key is what keeps a MAC key/message split ambiguous
        // pairs apart: "ab"/"c" and "a"/"bc" must not collide.
        assert_ne!(mac(b"ab", b"c", T_MSGMAC), mac(b"a", b"bc", T_MSGMAC));
    }
}
