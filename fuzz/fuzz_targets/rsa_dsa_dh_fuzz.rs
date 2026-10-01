#![no_main]

//! RSA / DSA / DH fuzzing. RSA uses a fixed 1024-bit key generated once per
//! process with a deterministic RNG (key generation is too slow to run per
//! input); DSA regenerates keys from fuzzed seeds; DH uses small fuzzed
//! moduli so agreement stays cheap.

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use crown::bn::Bn;
use crown::dsa;
use crown::envelope::EvpHash;
use crown::rsa::RsaPrivateKey;
use libfuzzer_sys::fuzz_target;

#[path = "common/det_rng.rs"]
mod common;

use common::DetRng;

#[derive(Arbitrary, Debug)]
enum Action {
    RsaPkcs1RoundTrip {
        msg: Vec<u8>,
    },
    RsaOaepRoundTrip {
        hash: u8,
        msg: Vec<u8>,
    },
    RsaSignRoundTrip {
        pss: bool,
        salt: u8,
        msg: Vec<u8>,
    },
    RsaDecryptFuzzed {
        ct: Vec<u8>,
    },
    RsaVerifyFuzzed {
        sig: Vec<u8>,
        salt: u8,
    },
    RsaRaw {
        m: Vec<u8>,
    },
    RsaPubFromComponents {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    DsaRoundTrip {
        msg: Vec<u8>,
        seed: u64,
        mutate: bool,
    },
    DsaVerifyFuzzed {
        msg: Vec<u8>,
        r: Vec<u8>,
        s: Vec<u8>,
    },
    DhAgree {
        p: Vec<u8>,
        g: Vec<u8>,
        seed_a: u64,
        seed_b: u64,
    },
    DhFuzzedPeer {
        p: Vec<u8>,
        g: Vec<u8>,
        seed: u64,
        peer: Vec<u8>,
    },
}

static RSA_KEY: OnceLock<RsaPrivateKey> = OnceLock::new();

fn rsa_key() -> &'static RsaPrivateKey {
    RSA_KEY.get_or_init(|| {
        RsaPrivateKey::generate(1024, 65537, &mut DetRng::new(0x5EED_5EED_5EED_5EED))
            .expect("rsa-1024 keygen")
    })
}

static DSA_KEY: OnceLock<dsa::DsaKeyPair> = OnceLock::new();

fn dsa_key() -> &'static dsa::DsaKeyPair {
    DSA_KEY.get_or_init(|| {
        dsa::generate(&dsa::dsa_2048_256(), &mut DetRng::new(0xD5A_5EED)).expect("dsa keygen")
    })
}

/// A small odd modulus (<= 256 bits) for cheap DH modexp.
fn small_modulus(v: &[u8]) -> Option<Bn> {
    let n = v.len().min(32);
    if n == 0 {
        return None;
    }
    let mut bytes = v[..n].to_vec();
    bytes[0] |= 0x80;
    let last = n - 1;
    bytes[last] |= 1;
    let p = Bn::from_be_bytes(&bytes);
    if p.lt(&Bn::from_u64(7)) {
        None
    } else {
        Some(p)
    }
}

fuzz_target!(|action: Action| {
    match action {
        Action::RsaPkcs1RoundTrip { msg } => {
            let key = rsa_key();
            let max = key.public().size() - 11;
            let msg = &msg[..msg.len().min(max)];
            let msg = if msg.is_empty() { b"\x01" } else { msg };
            let mut rng = DetRng::new(0xAB);
            let ct = key.public().encrypt_pkcs1v15(&mut rng, msg).unwrap();
            assert_eq!(key.decrypt_pkcs1v15(&ct).unwrap(), msg, "pkcs1 round trip");
        }
        Action::RsaOaepRoundTrip { hash, msg } => {
            let key = rsa_key();
            // For the 1024-bit key the message bound is k - 2*h_len - 2, so
            // only SHA-1/SHA-256/SHA-384 admit non-empty messages.
            let (factory, h_len): (fn() -> crown::error::CryptoResult<EvpHash>, usize) =
                match hash % 3 {
                    0 => (EvpHash::new_sha1, 20),
                    1 => (EvpHash::new_sha256, 32),
                    _ => (EvpHash::new_sha384, 48),
                };
            let max = key.public().size().saturating_sub(2 * h_len + 2);
            if max == 0 {
                return;
            }
            let msg = &msg[..msg.len().min(max)];
            let mut rng = DetRng::new(0xCD);
            if let Ok(ct) = key.public().encrypt_oaep(factory, &mut rng, msg) {
                assert_eq!(
                    key.decrypt_oaep(factory, &ct).unwrap(),
                    msg,
                    "oaep round trip"
                );
            }
        }
        Action::RsaSignRoundTrip { pss, salt, msg } => {
            let key = rsa_key();
            let msg = &msg[..msg.len().min(128)];
            let sig = key.sign_pkcs1v15(EvpHash::new_sha256, msg).unwrap();
            assert!(
                key.public()
                    .verify_pkcs1v15(EvpHash::new_sha256, msg, &sig)
                    .unwrap(),
                "pkcs1 verify rejected its own signature"
            );
            if pss {
                let mut rng = DetRng::new(0xEF);
                let salt_len = (salt % 33) as usize;
                let sig = key
                    .sign_pss(EvpHash::new_sha256, msg, salt_len, &mut rng)
                    .unwrap();
                assert!(
                    key.public()
                        .verify_pss(EvpHash::new_sha256, msg, &sig, salt_len)
                        .unwrap(),
                    "pss verify rejected its own signature"
                );
                let mut bad = sig;
                let at = (salt as usize) % bad.len();
                bad[at] ^= 1;
                assert!(
                    !key.public()
                        .verify_pss(EvpHash::new_sha256, msg, &bad, salt_len)
                        .unwrap(),
                    "pss verify accepted a mutated signature"
                );
            }
        }
        Action::RsaDecryptFuzzed { ct } => {
            let key = rsa_key();
            let _ = key.decrypt_raw(&ct);
            let _ = key.decrypt_pkcs1v15(&ct);
            let _ = key.decrypt_oaep(EvpHash::new_sha256, &ct);
        }
        Action::RsaVerifyFuzzed { sig, salt } => {
            let key = rsa_key();
            let msg = b"fuzz";
            let _ = key.public().verify_pkcs1v15(EvpHash::new_sha256, msg, &sig);
            let _ = key
                .public()
                .verify_pss(EvpHash::new_sha256, msg, &sig, (salt % 33) as usize);
        }
        Action::RsaRaw { m } => {
            let key = rsa_key();
            let n = Bn::from_be_bytes(&key.public().n());
            let k = key.public().size();
            let m_bn = Bn::from_be_bytes(&m[..m.len().min(k)]).modulus(&n);
            if m_bn.is_zero() {
                return;
            }
            let m_bytes = m_bn.to_be_bytes_padded(k).unwrap();
            let ct = key.public().encrypt_raw(&m_bytes).unwrap();
            assert_eq!(key.decrypt_raw(&ct).unwrap(), m_bytes, "raw round trip");
        }
        Action::RsaPubFromComponents { n, e } => {
            if let Ok(pub_key) = crown::rsa::RsaPublicKey::from_components(&n, &e) {
                let _ = pub_key.encrypt_raw(b"\x02");
            }
        }
        Action::DsaRoundTrip { msg, seed, mutate } => {
            let params = dsa::dsa_2048_256();
            let mut rng = DetRng::new(seed);
            if let Ok(key) = dsa::generate(&params, &mut rng) {
                let (r, s) = dsa::sign_sha256(&key, &msg, &mut rng).unwrap();
                assert!(
                    dsa::verify_sha256(&params, &key.y, &msg, &r, &s).unwrap(),
                    "dsa verify rejected its own signature"
                );
                if mutate {
                    let s2 = s.add(&Bn::one()).modulus(&params.q);
                    assert!(
                        !dsa::verify_sha256(&params, &key.y, &msg, &r, &s2).unwrap(),
                        "dsa verify accepted a mutated signature"
                    );
                }
            }
        }
        Action::DsaVerifyFuzzed { msg, r, s } => {
            let params = dsa::dsa_2048_256();
            let y = &dsa_key().y;
            let r = Bn::from_be_bytes(&r[..r.len().min(32)]);
            let s = Bn::from_be_bytes(&s[..s.len().min(32)]);
            let _ = dsa::verify_sha256(&params, y, &msg, &r, &s);
        }
        Action::DhAgree {
            p,
            g,
            seed_a,
            seed_b,
        } => {
            let Some(p) = small_modulus(&p) else {
                return;
            };
            let g = Bn::from_be_bytes(&g[..g.len().min(8)]);
            let mut rng_a = DetRng::new(seed_a);
            let mut rng_b = DetRng::new(seed_b);
            if let (Ok((a_priv, a_pub)), Ok((b_priv, b_pub))) = (
                crown::dh::generate(&p, &g, &mut rng_a),
                crown::dh::generate(&p, &g, &mut rng_b),
            ) {
                let s1 = crown::dh::agree(&p, &a_priv, &b_pub).unwrap();
                let s2 = crown::dh::agree(&p, &b_priv, &a_pub).unwrap();
                assert_eq!(s1, s2, "dh asymmetry");
            }
        }
        Action::DhFuzzedPeer { p, g, seed, peer } => {
            let Some(p) = small_modulus(&p) else {
                return;
            };
            let g = Bn::from_be_bytes(&g[..g.len().min(8)]);
            let mut rng = DetRng::new(seed);
            if let Ok((priv_key, _)) = crown::dh::generate(&p, &g, &mut rng) {
                let peer = Bn::from_be_bytes(&peer[..peer.len().min(64)]);
                let _ = crown::dh::agree(&p, &priv_key, &peer);
            }
        }
    }
});
