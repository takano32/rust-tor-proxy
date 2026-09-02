//! Ed25519 point arithmetic, for one job: blinding an onion service's public
//! key (rend-spec/keyblinding-scheme.md).
//!
//! This is the only cryptography in the project that is not OpenSSL's, because
//! OpenSSL exposes Ed25519 only as sign/verify and has no API for `h * A`.
//! Nothing secret passes through here: `A` is in the `.onion` address and `h`
//! is derived from public values, so the code may branch on its inputs, and
//! the double-and-add below deliberately does. A bug would point us at the
//! wrong directory nodes, not weaken anything.
//!
//! Field elements are five 51-bit limbs in a `u64` each, with products
//! accumulated in `u128` -- the usual 64-bit layout for `GF(2^255 - 19)`.
//! Points are extended twisted Edwards coordinates `(X, Y, Z, T)` on
//! `-x^2 + y^2 = 1 + d x^2 y^2`, where `x = X/Z`, `y = Y/Z` and `T = XY/Z`.

use std::io;

use crate::util::invalid_data;

const MASK: u64 = (1u64 << 51) - 1;

/// An element of `GF(2^255 - 19)`. Limbs are kept below `2^52` between
/// operations, which leaves the headroom `mul` and `sub` need.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// `d = -121665/121666`, the curve constant, and `2d` for point addition.
    const D: Fe = Fe([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);
    const D2: Fe = Fe([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);
    /// `sqrt(-1)`, needed when the square root comes out with the wrong sign.
    const SQRT_M1: Fe = Fe([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);

    /// Propagate carries so every limb is back under `2^51` (bar a bit of
    /// slack in limb 1). The result is congruent, not canonical.
    fn reduce(mut limbs: [u64; 5]) -> Fe {
        let carry = [
            limbs[0] >> 51,
            limbs[1] >> 51,
            limbs[2] >> 51,
            limbs[3] >> 51,
            limbs[4] >> 51,
        ];
        for limb in limbs.iter_mut() {
            *limb &= MASK;
        }
        // 2^255 = 19 (mod p), so the top carry folds back into limb 0.
        limbs[0] += carry[4] * 19;
        limbs[1] += carry[0];
        limbs[2] += carry[1];
        limbs[3] += carry[2];
        limbs[4] += carry[3];
        Fe(limbs)
    }

    /// Little-endian, ignoring bit 255 the way Ed25519 decoding does.
    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let word = |at: usize| -> u64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(buf)
        };
        Fe([
            word(0) & MASK,
            (word(6) >> 3) & MASK,
            (word(12) >> 6) & MASK,
            (word(19) >> 1) & MASK,
            (word(24) >> 12) & MASK,
        ])
    }

    /// The canonical little-endian encoding: fully reduced modulo `p`.
    fn to_bytes(self) -> [u8; 32] {
        let mut l = Fe::reduce(self.0).0;
        // Add 19 and see whether it carries past 2^255: that is exactly the
        // test for "this value is at least p", and q is the quotient.
        let mut q = (l[0] + 19) >> 51;
        for limb in l.iter().skip(1) {
            q = (limb + q) >> 51;
        }
        l[0] += 19 * q;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        l[4] &= MASK;

        let mut out = [0u8; 32];
        // Each limb spans 51 bits, so limbs straddle byte boundaries at
        // 6, 12, 19 and 25.
        for (i, chunk) in [(0usize, 0usize), (1, 51), (2, 102), (3, 153), (4, 204)] {
            let value = l[i];
            for bit in 0..51 {
                if (value >> bit) & 1 == 1 {
                    let position = chunk + bit;
                    out[position / 8] |= 1 << (position % 8);
                }
            }
        }
        out
    }

    fn add(self, other: Fe) -> Fe {
        Fe::reduce([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
        ])
    }

    /// `self - other`, computed as `self + 16p - other` so that no limb can
    /// wrap below zero.
    fn sub(self, other: Fe) -> Fe {
        // 16 * p, limb by limb.
        const P16: [u64; 5] = [
            (16 << 51) - 16 * 19,
            (16 << 51) - 16,
            (16 << 51) - 16,
            (16 << 51) - 16,
            (16 << 51) - 16,
        ];
        Fe::reduce([
            self.0[0] + P16[0] - other.0[0],
            self.0[1] + P16[1] - other.0[1],
            self.0[2] + P16[2] - other.0[2],
            self.0[3] + P16[3] - other.0[3],
            self.0[4] + P16[4] - other.0[4],
        ])
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(self, other: Fe) -> Fe {
        let a = self.0;
        let b = other.0;
        // Terms that wrap past limb 4 come back multiplied by 19.
        let b19 = [b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let m = |x: u64, y: u64| (x as u128) * (y as u128);

        let c0 =
            m(a[0], b[0]) + m(a[4], b19[0]) + m(a[3], b19[1]) + m(a[2], b19[2]) + m(a[1], b19[3]);
        let c1 =
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b19[1]) + m(a[3], b19[2]) + m(a[2], b19[3]);
        let c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b19[2]) + m(a[3], b19[3]);
        let c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b19[3]);
        let c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

        const MASK128: u128 = (1u128 << 51) - 1;
        let mut carry = c0 >> 51;
        let mut out = [0u64; 5];
        out[0] = (c0 & MASK128) as u64;
        for (index, value) in [c1, c2, c3, c4].into_iter().enumerate() {
            let value = value + carry;
            carry = value >> 51;
            out[index + 1] = (value & MASK128) as u64;
        }
        out[0] += (carry as u64) * 19;
        out[1] += out[0] >> 51;
        out[0] &= MASK;
        Fe(out)
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    /// `self^(2^k)`.
    fn pow2k(self, k: u32) -> Fe {
        let mut out = self;
        for _ in 0..k {
            out = out.square();
        }
        out
    }

    /// `(self^(2^250 - 1), self^11)`, the shared part of the two exponent
    /// chains below.
    fn pow22501(self) -> (Fe, Fe) {
        let t0 = self.square(); //         2
        let t1 = t0.pow2k(2); //           8
        let t2 = self.mul(t1); //          9
        let t3 = t0.mul(t2); //           11
        let t4 = t3.square(); //          22
        let t5 = t2.mul(t4); //     2^5 - 2^0
        let t6 = t5.pow2k(5); //   2^10 - 2^5
        let t7 = t6.mul(t5); //    2^10 - 2^0
        let t8 = t7.pow2k(10); //  2^20 - 2^10
        let t9 = t8.mul(t7); //    2^20 - 2^0
        let t10 = t9.pow2k(20); // 2^40 - 2^20
        let t11 = t10.mul(t9); //  2^40 - 2^0
        let t12 = t11.pow2k(10); //2^50 - 2^10
        let t13 = t12.mul(t7); //  2^50 - 2^0
        let t14 = t13.pow2k(50); //2^100 - 2^50
        let t15 = t14.mul(t13); // 2^100 - 2^0
        let t16 = t15.pow2k(100); //2^200 - 2^100
        let t17 = t16.mul(t15); // 2^200 - 2^0
        let t18 = t17.pow2k(50); //2^250 - 2^50
        (t18.mul(t13), t3) //      2^250 - 2^0
    }

    /// `self^(p-2)`, which is `1/self` for every non-zero element.
    fn invert(self) -> Fe {
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(t3) // 2^255 - 2^5 + 11 = p - 2
    }

    /// `self^((p-5)/8)`, the exponent that turns `u*v^7` into a square root.
    fn pow_p58(self) -> Fe {
        let (t19, _) = self.pow22501();
        t19.pow2k(2).mul(self) // 2^252 - 3
    }

    fn equals(self, other: Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    /// Ed25519 calls an element negative when its canonical encoding is odd.
    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

/// A curve point in extended coordinates.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    fn identity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    /// Recover a point from its 32-byte encoding: `y` in the low 255 bits and
    /// the sign of `x` in the top one.
    fn decompress(bytes: &[u8; 32]) -> Option<Point> {
        let sign = bytes[31] >> 7;
        let mut encoded_y = *bytes;
        encoded_y[31] &= 0x7f;
        let y = Fe::from_bytes(&encoded_y);

        // x^2 = (y^2 - 1) / (d y^2 + 1)
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = y2.mul(Fe::D).add(Fe::ONE);
        let mut x = sqrt_ratio(u, v)?;

        // A zero x has only one encoding, so the sign bit must be clear.
        if x.is_zero() && sign == 1 {
            return None;
        }
        if x.is_negative() != (sign == 1) {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    fn compress(self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x.mul(recip);
        let y = self.y.mul(recip);
        let mut out = y.to_bytes();
        out[31] |= (x.is_negative() as u8) << 7;
        out
    }

    /// add-2008-hwcd-3 for the twisted Edwards curve with `a = -1`.
    fn add(self, other: Point) -> Point {
        let a = self.y.sub(self.x).mul(other.y.sub(other.x));
        let b = self.y.add(self.x).mul(other.y.add(other.x));
        let c = self.t.mul(Fe::D2).mul(other.t);
        let d = self.z.mul(other.z);
        let d = d.add(d);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// dbl-2008-hwcd, likewise for `a = -1`.
    fn double(self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(c);
        let d = a.neg();
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    /// `scalar * self`, scalar little-endian. Variable time on purpose: see
    /// the module comment.
    fn mul_scalar(self, scalar: &[u8; 32]) -> Point {
        let mut result = Point::identity();
        for bit in (0..256).rev() {
            result = result.double();
            if (scalar[bit / 8] >> (bit % 8)) & 1 == 1 {
                result = result.add(self);
            }
        }
        result
    }
}

/// `sqrt(u/v)` when it exists, following ref10: compute a candidate, then fix
/// it up by `sqrt(-1)` if the square came out negated.
fn sqrt_ratio(u: Fe, v: Fe) -> Option<Fe> {
    let v3 = v.square().mul(v);
    let v7 = v3.square().mul(v);
    let candidate = u.mul(v3).mul(u.mul(v7).pow_p58());

    let check = v.mul(candidate.square());
    if check.equals(u) {
        return Some(candidate);
    }
    if check.equals(u.neg()) {
        return Some(candidate.mul(Fe::SQRT_M1));
    }
    None
}

/// Clamp a blinding factor the way Ed25519 clamps a secret scalar.
///
/// rend-spec derives `h` as a plain hash; both C Tor's
/// `ed25519_donna_blind_public_key` and the reference `ed25519_exts_ref.py`
/// clamp it before use, so the raw hash is never the multiplier.
fn clamp(param: &[u8; 32]) -> [u8; 32] {
    let mut h = *param;
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    h
}

/// `A' = h * A`: the blinded public key for one time period.
///
/// `param` is the unclamped blinding factor from
/// [`crate::tor::hs::blind`]; clamping happens here.
pub fn blind_public_key(public_key: &[u8; 32], param: &[u8; 32]) -> io::Result<[u8; 32]> {
    let point = Point::decompress(public_key)
        .ok_or_else(|| invalid_data("onion service key is not a point on curve25519"))?;
    Ok(point.mul_scalar(&clamp(param)).compress())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    fn key(hex: &str) -> [u8; 32] {
        hex_decode(hex).unwrap().try_into().unwrap()
    }

    /// The three hard-coded curve constants, checked against their
    /// definitions rather than trusted as typed.
    #[test]
    fn curve_constants_are_what_they_claim() {
        let small = |n: u64| Fe([n, 0, 0, 0, 0]);
        // d * 121666 == -121665
        assert!(Fe::D.mul(small(121666)).equals(small(121665).neg()));
        assert!(Fe::D2.equals(Fe::D.add(Fe::D)));
        // sqrt(-1)^2 == -1
        assert!(Fe::SQRT_M1.square().equals(Fe::ONE.neg()));
    }

    #[test]
    fn field_arithmetic_round_trips() {
        // p - 1 is the largest canonical value, and the encoding must survive.
        let p_minus_1 = Fe::ONE.neg();
        assert_eq!(
            p_minus_1.to_bytes(),
            key("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        );
        assert!(Fe::from_bytes(&p_minus_1.to_bytes()).equals(p_minus_1));
        assert!(p_minus_1.add(Fe::ONE).is_zero());

        // A non-canonical encoding of zero must still reduce to zero.
        let p = key("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        assert!(Fe::from_bytes(&p).is_zero());

        for seed in 1..16u8 {
            let a = Fe::from_bytes(&[seed.wrapping_mul(37); 32]);
            assert!(a.mul(a.invert()).equals(Fe::ONE));
            assert!(a.square().equals(a.mul(a)));
            assert!(a.sub(a).is_zero());
            assert!(a.neg().add(a).is_zero());
            assert!(Fe::from_bytes(&a.to_bytes()).equals(a));
        }
        assert!(Fe::ZERO.is_zero());
        assert!(!Fe::ONE.is_zero());
        assert!(Fe::ONE.is_negative());
        assert!(!Fe::ONE.add(Fe::ONE).is_negative());
    }

    /// Decompress then compress must be the identity on real public keys, and
    /// garbage that is not on the curve must be refused.
    #[test]
    fn decompression_round_trips() {
        // The public keys from RFC 8032 section 7.1, tests 1 to 3.
        for hex in [
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ] {
            let bytes = key(hex);
            let point = Point::decompress(&bytes).expect("a real public key must decompress");
            assert_eq!(point.compress(), bytes);
        }

        // y = 2 has no matching x on this curve.
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        assert!(Point::decompress(&off_curve).is_none());
        // x = 0 with the sign bit set is not a canonical encoding.
        let mut identity_wrong_sign = [0u8; 32];
        identity_wrong_sign[0] = 1;
        identity_wrong_sign[31] = 0x80;
        assert!(Point::decompress(&identity_wrong_sign).is_none());
    }

    #[test]
    fn group_law_holds() {
        let base = Point::decompress(&key(
            "5866666666666666666666666666666666666666666666666666666666666666",
        ))
        .unwrap();
        let identity = Point::identity();
        assert_eq!(identity.compress(), Fe::ONE.to_bytes());
        assert_eq!(base.add(identity).compress(), base.compress());
        assert_eq!(identity.double().compress(), identity.compress());
        assert_eq!(base.double().compress(), base.add(base).compress());

        // 1 * P == P, and 2 * P == P + P.
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(base.mul_scalar(&one).compress(), base.compress());
        let mut two = [0u8; 32];
        two[0] = 2;
        assert_eq!(base.mul_scalar(&two).compress(), base.double().compress());
        assert_eq!(
            base.mul_scalar(&[0u8; 32]).compress(),
            identity.compress(),
            "multiplying by zero must give the identity"
        );
    }

    /// C Tor's own blinding vectors, from `src/test/ed25519_vectors.inc`
    /// (generated by `ed25519_exts_ref.py`). The parameters there are the raw,
    /// unclamped values, which is why `blind_public_key` clamps.
    #[test]
    fn ctor_blinding_vectors() {
        const PUBLIC: [&str; 10] = [
            "c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894",
            "1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d",
            "081faa81992e360ea22c06af1aba096e7a73f1c665bc8b3e4e531c46455fd1dd",
            "73cfa1189a723aad7966137cbffa35140bb40d7e16eae4c40b79b5f0360dd65a",
            "66c1a77104d86461b6f98f73acf3cd229c80624495d2d74d6fda1e940080a96b",
            "d21c294db0e64cb2d8976625786ede1d9754186ae8197a64d72f68c792eecc19",
            "c4d58b4cf85a348ff3d410dd936fa460c4f18da962c01b1963792b9dcc8a6ea6",
            "95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            "95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
            "95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
        ];
        const PARAMS: [&str; 10] = [
            "54a513898b471d1d448a2f3c55c1de2c0ef718c447b04497eeb999ed32027823",
            "831e9b5325b5d31b7ae6197e9c7a7baf2ec361e08248bce055908971047a2347",
            "ac78a1d46faf3bfbbdc5af5f053dc6dc9023ed78236bec1760dadfd0b2603760",
            "f9c84dc0ac31571507993df94da1b3d28684a12ad14e67d0a068aba5c53019fc",
            "b1fe79d1dec9bc108df69f6612c72812755751f21ecc5af99663b30be8b9081f",
            "81f1512b63ab5fb5c1711a4ec83d379c420574aedffa8c3368e1c3989a3a0084",
            "97f45142597c473a4b0e9a12d64561133ad9e1155fe5a9807fe6af8a93557818",
            "3f44f6a5a92cde816635dfc12ade70539871078d2ff097278be2a555c9859cd0",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ];
        const BLINDED: [&str; 10] = [
            "1fc1fa4465bd9d4956fdbdc9d3acb3c7019bb8d5606b951c2e1dfe0b42eaeb41",
            "1cbbd4a88ce8f165447f159d9f628ada18674158c4f7c5ead44ce8eb0fa6eb7e",
            "c5419ad133ffde7e0ac882055d942f582054132b092de377d587435722deb028",
            "3e08d0dc291066272e313014bfac4d39ad84aa93c038478a58011f431648105f",
            "59381f06acb6bf1389ba305f70874eed3e0f2ab57cdb7bc69ed59a9b8899ff4d",
            "2b946a484344eb1c17c89dd8b04196a84f3b7222c876a07a4cece85f676f87d9",
            "c6b585129b135f8769df2eba987e76e089e80ba3a2a6729134d3b28008ac098e",
            "0eefdc795b59cabbc194c6174e34ba9451e8355108520554ec285acabebb34ac",
            "312404d06a0a9de489904b18d5233e83a50b225977fa8734f2c897a73c067952",
            "952a908a4a9e0e5176a2549f8f328955aca6817a9fdc59e3acec5dec50838108",
        ];

        for i in 0..10 {
            assert_eq!(
                blind_public_key(&key(PUBLIC[i]), &key(PARAMS[i])).unwrap(),
                key(BLINDED[i]),
                "vector {i}"
            );
        }
    }

    #[test]
    fn clamping_matches_the_reference() {
        let clamped = clamp(&[0xffu8; 32]);
        assert_eq!(clamped[0], 0xf8);
        assert_eq!(clamped[31], 0x7f);
        let clamped = clamp(&[0x00u8; 32]);
        assert_eq!(clamped[0], 0x00);
        assert_eq!(clamped[31], 0x40);
    }

    #[test]
    fn rejects_a_key_that_is_not_on_the_curve() {
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert!(blind_public_key(&bad, &[1u8; 32]).is_err());
    }
}
