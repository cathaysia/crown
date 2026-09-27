//! Golden vectors for the asymmetric primitives: RSA (PKCS#1 v1.5 verify and
//! decrypt, PSS verify, OAEP decrypt) from wycheproof, and Ed25519 from
//! wycheproof plus pyca/cryptography's `sign.input`.

mod utils;
mod wycheproof;

use crown::envelope::EvpHash;
use crown::error::CryptoResult;
use crown::rsa::{RsaPrivateKey, RsaPublicKey};
use wycheproof::eddsa::*;
use wycheproof::rsa::*;

/// Map a wycheproof digest name onto the `HashFactory` crown wants. The
/// SHA-3 and SHA-512/t digests are deliberately absent: `emsa_pkcs1_encode`
/// selects its `DigestInfo` prefix by digest *length*, so those would be
/// encoded as SHA-256/SHA-224.
fn hash_of(name: &str) -> Option<fn() -> CryptoResult<EvpHash>> {
    Some(match name {
        "SHA-1" => EvpHash::new_sha1,
        "SHA-224" => EvpHash::new_sha224,
        "SHA-256" => EvpHash::new_sha256,
        "SHA-384" => EvpHash::new_sha384,
        "SHA-512" => EvpHash::new_sha512,
        "SHA-512/224" => EvpHash::new_sha512_224,
        "SHA-512/256" => EvpHash::new_sha512_256,
        _ => return None,
    })
}

fn hex_or_empty(v: &Option<String>) -> Vec<u8> {
    hex::decode(v.as_deref().unwrap_or_default()).unwrap()
}

/// A private key from the PKCS#8 blob the groups carry (it holds the CRT
/// parameters, which keeps the decryption tests fast).
fn private_key(group: &RsaTestGroup) -> Option<RsaPrivateKey> {
    let der = group.private_key_pkcs8.as_ref()?;
    let (n, e, d, p, q, dp, dq, qinv) =
        crown::rsa::der::parse_pkcs8_rsa_private_key(&hex::decode(der).ok()?).ok()?;
    RsaPrivateKey::from_components(
        &n,
        &e,
        &d,
        Some(&p),
        Some(&q),
        Some(&dp),
        Some(&dq),
        Some(&qinv),
    )
    .ok()
}

#[test]
fn test_wycheproof_rsa_pkcs1_verify() {
    let mut checked = 0usize;

    for file in PKCS1_SIG_TESTS {
        let test = get_rsa_test(file);

        for group in test.test_groups {
            let (Some(n), Some(e)) = (&group.n, &group.e) else {
                continue;
            };
            let Some(hash) = group.sha.as_deref().and_then(hash_of) else {
                continue;
            };
            let Ok(key) =
                RsaPublicKey::from_components(&hex::decode(n).unwrap(), &hex::decode(e).unwrap())
            else {
                continue;
            };

            for t in group.tests {
                let msg = hex_or_empty(&t.msg);
                let sig = hex_or_empty(&t.sig);
                let ok = key.verify_pkcs1v15(hash, &msg, &sig).unwrap_or(false);

                match t.result {
                    Some(RsaTestVectorResult::Valid) => {
                        assert!(
                            ok,
                            "{file}: valid PKCS#1 v1.5 signature rejected (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Invalid) => {
                        assert!(
                            !ok,
                            "{file}: invalid PKCS#1 v1.5 signature accepted (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 1000, "only {checked} vectors were verified");
}

#[test]
fn test_wycheproof_rsa_pss_verify() {
    let mut checked = 0usize;

    for file in PSS_TESTS {
        let test = get_rsa_test(file);

        for group in test.test_groups {
            let (Some(n), Some(e)) = (&group.n, &group.e) else {
                continue;
            };
            let Some(hash) = group.sha.as_deref().and_then(hash_of) else {
                continue;
            };
            // crown derives the MGF1 mask with the message digest.
            if group.mgf.as_deref() != Some("MGF1")
                || group.mgf_sha.as_deref() != group.sha.as_deref()
            {
                continue;
            }
            let Some(salt_len) = group.s_len else {
                continue;
            };
            let Ok(key) =
                RsaPublicKey::from_components(&hex::decode(n).unwrap(), &hex::decode(e).unwrap())
            else {
                continue;
            };

            for t in group.tests {
                let msg = hex_or_empty(&t.msg);
                let sig = hex_or_empty(&t.sig);
                let ok = key
                    .verify_pss(hash, &msg, &sig, salt_len.max(0) as usize)
                    .unwrap_or(false);

                match t.result {
                    Some(RsaTestVectorResult::Valid) => {
                        assert!(
                            ok,
                            "{file}: valid PSS signature rejected (tc {}, salt {salt_len})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Invalid) => {
                        assert!(
                            !ok,
                            "{file}: invalid PSS signature accepted (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 400, "only {checked} vectors were verified");
}

#[test]
fn test_wycheproof_rsa_oaep_decrypt() {
    let mut checked = 0usize;

    for file in OAEP_TESTS {
        let test = get_rsa_test(file);

        for group in test.test_groups {
            let Some(hash) = group.sha.as_deref().and_then(hash_of) else {
                continue;
            };
            // crown derives the MGF1 mask with the message digest and only
            // supports the empty label.
            if group.mgf.as_deref() != Some("MGF1")
                || group.mgf_sha.as_deref() != group.sha.as_deref()
            {
                continue;
            }
            let Some(key) = private_key(&group) else {
                continue;
            };

            for t in group.tests {
                if !hex_or_empty(&t.label).is_empty() {
                    continue;
                }
                let msg = hex_or_empty(&t.msg);
                let ct = hex_or_empty(&t.ct);

                let ok = key
                    .decrypt_oaep(hash, &ct)
                    .map(|out| out == msg)
                    .unwrap_or(false);

                match t.result {
                    Some(RsaTestVectorResult::Valid) => {
                        assert!(
                            ok,
                            "{file}: valid OAEP ciphertext failed (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Invalid) => {
                        assert!(
                            !ok,
                            "{file}: invalid OAEP ciphertext accepted (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked >= 276, "only {checked} vectors were verified");
}

#[test]
fn test_wycheproof_rsa_pkcs1_decrypt() {
    let mut checked = 0usize;

    for file in PKCS1_DECRYPT_TESTS {
        let test = get_rsa_test(file);

        for group in test.test_groups {
            let Some(key) = private_key(&group) else {
                continue;
            };

            for t in group.tests {
                let msg = hex_or_empty(&t.msg);
                let ct = hex_or_empty(&t.ct);

                let ok = key
                    .decrypt_pkcs1v15(&ct)
                    .map(|out| out == msg)
                    .unwrap_or(false);

                match t.result {
                    Some(RsaTestVectorResult::Valid) => {
                        assert!(
                            ok,
                            "{file}: valid PKCS#1 v1.5 ciphertext failed (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Invalid) => {
                        assert!(
                            !ok,
                            "{file}: invalid PKCS#1 v1.5 ciphertext accepted (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(RsaTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 150, "only {checked} vectors were verified");
}

#[test]
fn test_wycheproof_ed25519_verify() {
    let mut checked = 0usize;

    for file in EDDSA_TESTS {
        let test = get_eddsa_test(file);

        for group in test.test_groups {
            // Both files carry the public key as a nested object; crown only
            // has Ed25519, so the Ed448 groups (57-byte keys) are skipped.
            let key = group
                .public_key
                .as_ref()
                .and_then(|k| k.pk.as_ref())
                .or_else(|| group.key.as_ref().and_then(|k| k.pk.as_ref()))
                .map(|k| hex::decode(k).unwrap());
            let Some(key) = key else { continue };
            let Ok(key): Result<[u8; 32], _> = key.try_into() else {
                continue;
            };

            for t in group.tests {
                let msg = hex_or_empty(&t.msg);
                let sig = hex_or_empty(&t.sig);
                let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
                    // Wrong signature length: rejected unless the vector is
                    // itself negative.
                    assert!(matches!(
                        t.result,
                        Some(EddsaTestVectorResult::Invalid)
                            | None
                            | Some(EddsaTestVectorResult::Acceptable)
                    ));
                    continue;
                };

                let ok = crown::ed25519::verify(&key, &sig, &msg);
                match t.result {
                    Some(EddsaTestVectorResult::Valid) => {
                        assert!(
                            ok,
                            "{file}: valid Ed25519 signature rejected (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(EddsaTestVectorResult::Invalid) => {
                        assert!(
                            !ok,
                            "{file}: invalid Ed25519 signature accepted (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(EddsaTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked >= 271, "only {checked} vectors were verified");
}

/// pyca/cryptography's `sign.input`: `sk:pk:msg:sig` lines, each 32-byte seed
/// used both for signing (deterministic) and verification.
#[test]
fn test_pyca_ed25519_sign() {
    let content = utils::read_pyca("asymmetric/Ed25519/sign.input");
    let mut checked = 0usize;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        // Secret key: 32-byte seed, sometimes with the public key appended.
        let sk = hex::decode(parts[0]).unwrap();
        let sk: [u8; 32] = sk[..32].try_into().unwrap();
        let public = hex::decode(parts[1]).unwrap();
        let msg = hex::decode(parts[2]).unwrap();
        // The last field is `sig || msg`.
        let sig_and_msg = hex::decode(parts[3]).unwrap();
        assert_eq!(sig_and_msg[64..], msg[..], "sig field does not end in msg");
        let sig = &sig_and_msg[..64];

        assert_eq!(
            crown::ed25519::public_from_secret(&sk).to_vec(),
            public,
            "public key mismatch for seed {}",
            parts[0]
        );
        assert_eq!(
            crown::ed25519::sign(&sk, &msg).to_vec(),
            sig.to_vec(),
            "signature mismatch for seed {}",
            parts[0]
        );
        let public: [u8; 32] = public.try_into().unwrap();
        let sig: [u8; 64] = sig.try_into().unwrap();
        assert!(crown::ed25519::verify(&public, &sig, &msg));
        checked += 1;
    }

    assert!(checked > 50, "only {checked} Ed25519 vectors were verified");
}

/// PKCS#1 v1.5 signing is deterministic, so the vectors pin the exact
/// signature (wycheproof marks them `acceptable` only because of the small
/// moduli and weak digests).
#[test]
fn test_wycheproof_rsa_pkcs1_sign() {
    let mut checked = 0usize;

    for file in PKCS1_SIGN_TESTS {
        let test = get_rsa_test(file);

        for group in test.test_groups {
            let Some(hash) = group.sha.as_deref().and_then(hash_of) else {
                continue;
            };
            let Some(key) = private_key(&group) else {
                continue;
            };

            for t in group.tests {
                let msg = hex_or_empty(&t.msg);
                let expected = hex_or_empty(&t.sig);
                let sig = key.sign_pkcs1v15(hash, &msg).unwrap();
                assert_eq!(
                    hex::encode(&sig),
                    hex::encode(&expected),
                    "{file}: signature for tc {}",
                    t.tc_id.unwrap_or_default()
                );
                assert!(key.public().verify_pkcs1v15(hash, &msg, &sig).unwrap());
                checked += 1;
            }
        }
    }

    assert!(
        checked >= 150,
        "only {checked} signing vectors were verified"
    );
}
