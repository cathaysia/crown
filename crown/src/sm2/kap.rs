//! SM2 key exchange (GB/T 32918.3-2016 / GM/T 0003.3).
//!
//! Both parties run the same computation over their own inputs
//! `(d, r, R = [r]G)` and the peer's `(P, R')`:
//!
//! * x̄ = 2^w + (x mod 2^w) with w = field_bits/2 - 1 (128 for SM2),
//! * t = (d + x̄·r) mod n,
//! * V = [t·h]P + [t·h·x̄']R' (h = 1, folded into t mod n),
//! * key = KDF(xV || yV || Z_initiator || Z_responder, klen) with the
//!   ANSI X9.63 KDF over SM3,
//! * confirmation tags: S1 = SM3(0x02 ‖ yV ‖ xV ‖ Z_A ‖ Z_B ‖ x1 ‖ y1 ‖
//!   x2 ‖ y2) and S2 = SM3(0x03 ‖ …) with A's ephemeral point as
//!   (x1, y1) and B's as (x2, y2) regardless of the computing side; the
//!   initiator verifies S1 and answers with S2.
//!
//! Z values are the SM2 signature ZA over each party's identity and
//! static public key ([`crate::sm2::compute_za`]). The curve is part of
//! [`KapInput`]; the GB/T 32918.3-2016 worked example uses the example
//! curve of GB/T 32918.1-2016 annex A, not SM2-P-256.

use crate::bn::Bn;
use crate::ec::{coord32, Curve, Point};
use crate::error::{CryptoError, CryptoResult};
use crate::hash::sm3::sum_sm3;
use crate::kdf::{sskdf::x963_derive_hash, HashFactory};
use crate::sm2::compute_za_on;

use alloc::vec;
use alloc::vec::Vec;

fn sm3_factory() -> HashFactory {
    crate::envelope::EvpHash::new_sm3
}

/// One side's SM2 key-exchange inputs.
pub struct KapInput<'a> {
    /// The curve both parties operate on.
    pub curve: &'a Curve,
    /// `true` for the initiator (A), `false` for the responder (B).
    pub is_initiator: bool,
    /// Static private key d.
    pub d: &'a Bn,
    /// Static public key of this party (used for its Z value).
    pub static_pub: &'a Point,
    /// Ephemeral private key r.
    pub r: &'a Bn,
    /// Own ephemeral public key `[r]G`.
    pub ephemeral_pub: &'a Point,
    /// Peer's static public key.
    pub peer_static_pub: &'a Point,
    /// Peer's ephemeral public key.
    pub peer_ephemeral_pub: &'a Point,
    /// Own identity (used for the Z value).
    pub id: &'a [u8],
    /// Peer's identity.
    pub peer_id: &'a [u8],
}

/// Derived key plus this side's confirmation tag.
pub struct KapOutput {
    /// The `klen`-byte shared key.
    pub key: Vec<u8>,
    /// Confirmation tag to send to the peer (S2 for the initiator,
    /// S1 for the responder).
    pub tag: Vec<u8>,
}

/// x̄ = 2^w + (x mod 2^w) with w = 127 for the 256-bit curves: the low
/// 127 bits of the field element with bit 127 set.
fn reduce(x: &Bn, w: usize) -> Bn {
    debug_assert_eq!(w, 127);
    let bytes = x.to_be_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[bytes.len() - 16..]);
    out[0] = (out[0] & 0x7f) | 0x80;
    Bn::from_be_bytes(&out)
}

/// SM2 key agreement. When `expected_peer_tag` is given (the confirmation
/// flow) the peer's tag is verified in constant time; mismatches fail with
/// [`CryptoError::AuthenticationFailed`].
pub fn key_agree(
    input: &KapInput,
    klen: usize,
    expected_peer_tag: Option<&[u8]>,
) -> CryptoResult<KapOutput> {
    let c = input.curve;
    let n = &c.n;
    // w = field_bits/2 - 1 (GB/T 32918.3 §6.1); 256-bit curves → 127.
    let w = 127usize;

    for p in [
        input.static_pub,
        input.ephemeral_pub,
        input.peer_static_pub,
        input.peer_ephemeral_pub,
    ] {
        if p.is_infinity() || !p.is_on_curve(c) {
            return Err(CryptoError::StrError("sm2: point not on curve"));
        }
    }

    // t = (d + x̄·r) mod n; U = [t]P_peer + [t·x̄']R_peer.
    let x_bar_self = reduce(&input.ephemeral_pub.x, w);
    let x_bar_peer = reduce(&input.peer_ephemeral_pub.x, w);
    let d = input.d.modulus(n);
    let r = input.r.modulus(n);
    if d.is_zero() || r.is_zero() {
        return Err(CryptoError::StrError("sm2: private key out of range"));
    }
    let t = d.add(&x_bar_self.modmul(&r, n)).modulus(n);
    let p1 = input.peer_static_pub.mul_with(c, &t);
    let k2 = t.modmul(&x_bar_peer, n);
    let p2 = input.peer_ephemeral_pub.mul_with(c, &k2);
    let u = p1.add_with(c, &p2);
    if u.is_infinity() {
        return Err(CryptoError::StrError("sm2: shared point is infinity"));
    }
    let xu = coord32(&u.x);
    let yu = coord32(&u.y);

    let za = compute_za_on(c, input.id, input.static_pub);
    let zb = compute_za_on(c, input.peer_id, input.peer_static_pub);
    let (z_first, z_second) = if input.is_initiator {
        (&za, &zb)
    } else {
        (&zb, &za)
    };

    // key = KDF(xU || yU || Z_initiator || Z_responder, klen).
    let mut z = Vec::with_capacity(64 + za.len() + zb.len());
    z.extend_from_slice(&xu);
    z.extend_from_slice(&yu);
    z.extend_from_slice(z_first);
    z.extend_from_slice(z_second);
    let key = x963_derive_hash(sm3_factory(), &z, &[], klen)?;

    // Confirmation tags (fixed A/B roles for the ephemeral coordinates):
    // inner = SM3(xU || Z_A || Z_B || x1 || y1 || x2 || y2) where 1 = A's
    // ephemeral point and 2 = B's; S1 = SM3(0x02 || yU || inner),
    // S2 = SM3(0x03 || yU || inner).
    let (ra, rb) = if input.is_initiator {
        (input.ephemeral_pub, input.peer_ephemeral_pub)
    } else {
        (input.peer_ephemeral_pub, input.ephemeral_pub)
    };
    let mut inner_in = Vec::with_capacity(32 + 2 * 64);
    inner_in.extend_from_slice(&xu);
    // Always Z_A first, then Z_B, regardless of the computing side.
    inner_in.extend_from_slice(z_first);
    inner_in.extend_from_slice(z_second);
    inner_in.extend_from_slice(&coord32(&ra.x));
    inner_in.extend_from_slice(&coord32(&ra.y));
    inner_in.extend_from_slice(&coord32(&rb.x));
    inner_in.extend_from_slice(&coord32(&rb.y));
    let inner = sum_sm3(&inner_in);

    let mut s1_in = vec![0x02u8];
    s1_in.extend_from_slice(&yu);
    s1_in.extend_from_slice(&inner);
    let s1 = sum_sm3(&s1_in);

    let mut s2_in = vec![0x03u8];
    s2_in.extend_from_slice(&yu);
    s2_in.extend_from_slice(&inner);
    let s2 = sum_sm3(&s2_in);

    let (tag, expected) = if input.is_initiator {
        (&s2[..], &s1[..])
    } else {
        (&s1[..], &s2[..])
    };
    if let Some(peer_tag) = expected_peer_tag {
        if !crate::utils::subtle::constant_time_eq(expected, peer_tag) {
            return Err(CryptoError::AuthenticationFailed);
        }
    }
    Ok(KapOutput {
        key,
        tag: tag.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::mul_base;

    fn bn(s: &str) -> Bn {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Bn::from_be_bytes(&bytes)
    }

    /// GB/T 32918.3-2016 appendix A example (values as used by
    /// BouncyCastle's SM2KeyExchangeTest).
    #[test]
    fn gbt32918_3_appendix_a() {
        let d_a = bn("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
        let r_a = bn("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        let d_b = bn("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
        let r_b = bn("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
        let id_a = b"ALICE123@YAHOO.COM";
        let id_b = b"BILL456@YAHOO.COM";

        // The GB/T 32918.3-2016 worked example uses the annex A example
        // curve of GB/T 32918.1-2016.
        let c = example_curve();
        let p_a = mul_base(&c, &d_a);
        let p_b = mul_base(&c, &d_b);
        let r_a_pub = mul_base(&c, &r_a);
        let r_b_pub = mul_base(&c, &r_b);

        // Initiator verifies the responder's S1 tag and returns S2.
        let a = key_agree(
            &KapInput {
                curve: &c,
                is_initiator: true,
                d: &d_a,
                static_pub: &p_a,
                r: &r_a,
                ephemeral_pub: &r_a_pub,
                peer_static_pub: &p_b,
                peer_ephemeral_pub: &r_b_pub,
                id: id_a,
                peer_id: id_b,
            },
            16,
            Some(&hex(
                "284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C",
            )),
        )
        .unwrap();
        assert_eq!(a.key, hex("55b0ac62a6b927ba23703832c853ded4"));
        assert_eq!(
            a.tag,
            hex("23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A")
        );

        // Responder verifies the initiator's S2 tag and returns S1.
        let b = key_agree(
            &KapInput {
                curve: &c,
                is_initiator: false,
                d: &d_b,
                static_pub: &p_b,
                r: &r_b,
                ephemeral_pub: &r_b_pub,
                peer_static_pub: &p_a,
                peer_ephemeral_pub: &r_a_pub,
                id: id_b,
                peer_id: id_a,
            },
            16,
            Some(&hex(
                "23444DAF8ED7534366CB901C84B3BDBB63504F4065C1116C91A4C00697E6CF7A",
            )),
        )
        .unwrap();
        assert_eq!(b.key, hex("55b0ac62a6b927ba23703832c853ded4"));
        assert_eq!(
            b.tag,
            hex("284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C")
        );

        // A wrong expected tag fails.
        let mut bad = hex("284C8F198F141B502E81250F1581C7E9EEB4CA6990F9E02DF388B45471F5BC5C");
        bad[0] ^= 1;
        let res = key_agree(
            &KapInput {
                curve: &c,
                is_initiator: true,
                d: &d_a,
                static_pub: &p_a,
                r: &r_a,
                ephemeral_pub: &r_a_pub,
                peer_static_pub: &p_b,
                peer_ephemeral_pub: &r_b_pub,
                id: id_a,
                peer_id: id_b,
            },
            16,
            Some(&bad),
        );
        assert!(matches!(res, Err(CryptoError::AuthenticationFailed)));
    }

    fn example_curve() -> Curve {
        Curve::from_parts(
            bn("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"),
            bn("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
            bn("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
            bn("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            bn("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
            bn("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"),
        )
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
