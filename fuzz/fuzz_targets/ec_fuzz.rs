#![no_main]

//! Elliptic-curve fuzzing: ECDSA/ECDH over P-256/384/521, SM2, Ed25519,
//! Ed448, X25519 and X448. Signatures round trip against verify; key
//! agreement is checked for symmetry; parsers must reject garbage without
//! panicking.

use arbitrary::Arbitrary;
use crown::bn::Bn;
use crown::ec::{CurveId, Point};
use libfuzzer_sys::fuzz_target;

#[path = "common/det_rng.rs"]
mod common;

use common::DetRng;

#[derive(Arbitrary, Debug)]
enum Action {
    Ecdsa {
        curve: u8,
        hash: u8,
        d: Vec<u8>,
        msg: Vec<u8>,
        seed: u64,
        mutate: bool,
    },
    Ecdh {
        curve: u8,
        seed_a: u64,
        seed_b: u64,
        peer: Vec<u8>,
    },
    PointRoundTrip {
        curve: u8,
        sec1: Vec<u8>,
    },
    Ed25519 {
        sk: Vec<u8>,
        msg: Vec<u8>,
        flip: u8,
    },
    Ed448 {
        sk: Vec<u8>,
        msg: Vec<u8>,
        ctx: Vec<u8>,
    },
    X25519 {
        a: Vec<u8>,
        b: Vec<u8>,
        peer: Vec<u8>,
    },
    X448 {
        a: Vec<u8>,
        b: Vec<u8>,
        peer: Vec<u8>,
    },
    Sm2 {
        d: Vec<u8>,
        msg: Vec<u8>,
        id: Vec<u8>,
        seed: u64,
    },
}

fn curve_of(id: u8) -> CurveId {
    match id % 3 {
        0 => CurveId::P256,
        1 => CurveId::P384,
        _ => CurveId::P521,
    }
}

fn scalar(v: &[u8], max: usize) -> Bn {
    let n = v.len().min(max);
    Bn::from_be_bytes(&v[..n])
}

fuzz_target!(|action: Action| {
    match action {
        Action::Ecdsa {
            curve,
            hash,
            d,
            msg,
            seed,
            mutate,
        } => {
            let id = curve_of(curve);
            let c = crown::ec::curve(id);
            let hash = match hash % 3 {
                0 => crown::ecdsa::DigestId::Sha256,
                1 => crown::ecdsa::DigestId::Sha384,
                _ => crown::ecdsa::DigestId::Sha512,
            };
            let d = scalar(&d, 66);
            let mut rng = DetRng::new(seed);
            if let Ok((r, s)) = crown::ecdsa::sign(id, hash, &d, &msg, &mut rng) {
                let pub_key = crown::ec::mul_base(&c, &d);
                assert!(
                    crown::ecdsa::verify(id, hash, &pub_key, &msg, &r, &s).unwrap(),
                    "ecdsa verify rejected its own signature"
                );
                if mutate {
                    let s2 = s.add(&Bn::one()).modulus(&c.n);
                    assert!(
                        !crown::ecdsa::verify(id, hash, &pub_key, &msg, &r, &s2).unwrap(),
                        "ecdsa verify accepted a mutated signature"
                    );
                }
                let bytes = pub_key.to_bytes_with(&c);
                let back = Point::from_bytes(&c, &bytes).unwrap();
                assert_eq!(back.to_bytes_with(&c), bytes, "sec1 round trip mismatch");
            }
        }
        Action::Ecdh {
            curve,
            seed_a,
            seed_b,
            peer,
        } => {
            let id = curve_of(curve);
            let mut rng_a = DetRng::new(seed_a);
            let mut rng_b = DetRng::new(seed_b);
            if let (Ok((a_priv, a_pub)), Ok((b_priv, b_pub))) = (
                crown::ecdh::generate(id, &mut rng_a),
                crown::ecdh::generate(id, &mut rng_b),
            ) {
                let s1 = crown::ecdh::agree(id, &a_priv, &b_pub).unwrap();
                let s2 = crown::ecdh::agree(id, &b_priv, &a_pub).unwrap();
                assert_eq!(s1, s2, "ecdh asymmetry");
                if let Ok(p) = Point::from_bytes(&crown::ec::curve(id), &peer) {
                    let _ = crown::ecdh::agree(id, &a_priv, &p);
                }
            }
        }
        Action::PointRoundTrip { curve, sec1 } => {
            let c = crown::ec::curve(curve_of(curve));
            if let Ok(p) = Point::from_bytes(&c, &sec1) {
                let bytes = p.to_bytes_with(&c);
                let back = Point::from_bytes(&c, &bytes).unwrap();
                assert_eq!(back.to_bytes_with(&c), bytes, "point round trip mismatch");
            }
        }
        Action::Ed25519 { sk, msg, flip } => {
            let sk: [u8; 32] = common::fixed(&sk);
            let public = crown::ed25519::public_from_secret(&sk);
            let sig = crown::ed25519::sign(&sk, &msg);
            assert!(
                crown::ed25519::verify(&public, &sig, &msg),
                "ed25519 verify rejected its own signature"
            );
            let mut bad = sig;
            bad[(flip % 64) as usize] ^= 1;
            assert!(
                !crown::ed25519::verify(&public, &bad, &msg),
                "ed25519 verify accepted a mutated signature"
            );
        }
        Action::Ed448 { sk, msg, ctx } => {
            let sk: [u8; 57] = common::fixed(&sk);
            let public = crown::ed448::public_from_secret(&sk);
            let ctx = &ctx[..ctx.len().min(255)];
            let sig = crown::ed448::sign(&sk, &msg, ctx);
            assert!(
                crown::ed448::verify(&public, &sig, &msg, ctx),
                "ed448 verify rejected its own signature"
            );
            let pre = crown::ed448::prehash(&msg);
            let sig_ph = crown::ed448::sign_ph(&sk, &pre, ctx);
            assert!(
                crown::ed448::verify_ph(&public, &sig_ph, &pre, ctx),
                "ed448ph verify rejected its own signature"
            );
        }
        Action::X25519 { a, b, peer } => {
            let a: [u8; 32] = common::fixed(&a);
            let b: [u8; 32] = common::fixed(&b);
            let a_pub = crown::x25519::public_from_private(&a);
            let b_pub = crown::x25519::public_from_private(&b);
            let s1 = crown::x25519::x25519(&a, &b_pub);
            let s2 = crown::x25519::x25519(&b, &a_pub);
            assert_eq!(s1, s2, "x25519 asymmetry");
            let peer: [u8; 32] = common::fixed(&peer);
            let shared = crown::x25519::x25519(&a, &peer);
            if peer.iter().all(|&x| x == 0) {
                assert!(shared.is_none(), "all-zero x25519 shared secret");
            }
        }
        Action::X448 { a, b, peer } => {
            let a: [u8; 56] = common::fixed(&a);
            let b: [u8; 56] = common::fixed(&b);
            let a_pub = crown::x448::public_from_private(&a);
            let b_pub = crown::x448::public_from_private(&b);
            let s1 = crown::x448::x448(&a, &b_pub);
            let s2 = crown::x448::x448(&b, &a_pub);
            assert_eq!(s1, s2, "x448 asymmetry");
            let peer: [u8; 56] = common::fixed(&peer);
            let shared = crown::x448::x448(&a, &peer);
            if peer.iter().all(|&x| x == 0) {
                assert!(shared.is_none(), "all-zero x448 shared secret");
            }
        }
        Action::Sm2 { d, msg, id, seed } => {
            let c = crown::sm2::sm2_curve();
            let d = scalar(&d, 64);
            let mut rng = DetRng::new(seed);
            if let Ok((r, s)) = crown::sm2::sign(&d, &msg, &id, &mut rng) {
                let pub_key = crown::ec::mul_base(&c, &d);
                assert!(
                    crown::sm2::verify(&pub_key, &msg, &id, &r, &s).unwrap(),
                    "sm2 verify rejected its own signature"
                );
                let _ = crown::sm2::compute_za(&id, &pub_key);
            }
            if let Ok((r, s)) = crown::sm2::sign_default_id(&d, &msg, &mut rng) {
                let pub_key = crown::ec::mul_base(&c, &d);
                assert!(
                    crown::sm2::verify_default_id(&pub_key, &msg, &r, &s).unwrap(),
                    "sm2 default-id verify rejected its own signature"
                );
            }
        }
    }
});
