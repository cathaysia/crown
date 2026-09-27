//! Golden vectors for the MAC family from the vendored wycheproof and
//! pyca/cryptography trees: CMAC, GMAC, KMAC, SipHash, Poly1305 and the HMAC
//! variants that have no wycheproof v0 file.

mod utils;
mod wycheproof;

use crown::block::aes::Aes;
use crown::block::BlockCipher;
use crown::hash::HashUser;
use crown::mac::cmac::Cmac as CmacMac;
use crown::mac::{cmac::Cmac, gmac::Gmac, kmac::Kmac128, kmac::Kmac256, siphash};
use wycheproof::mac::with_iv::MacWithIvTestVectorResult;
use utils::{parse_vectors, read_pyca};
use wycheproof::mac::*;

fn hex_to_bytes(s: &Option<String>) -> Vec<u8> {
    hex::decode(s.as_deref().unwrap_or_default()).unwrap()
}

/// CMAC over a 128-bit block cipher; `None` when the key is rejected.
fn cmac_tag<C: BlockCipher>(
    cipher: Result<C, crown::error::CryptoError>,
    msg: &[u8],
) -> Option<Vec<u8>> {
    let cipher = cipher.ok()?;
    let mut mac = Cmac::<C, 16>::new(cipher).ok()?;
    mac.write(msg);
    Some(mac.sum().to_vec())
}

#[test]
fn test_wycheproof_cmac() {
    let mut checked = 0usize;

    for file in CMAC_TESTS {
        let test = get_mac_test(file);
        let algorithm = test.algorithm.unwrap_or_default();

        for group in test.test_groups {
            let tag_size = group.tag_size.unwrap_or(128) as usize / 8;

            for t in group.tests {
                let key = hex_to_bytes(&t.key);
                let msg = hex_to_bytes(&t.msg);
                let expected = hex_to_bytes(&t.tag);

                // The AES/ARIA/Camellia key schedule rejects the short and
                // oversized keys of the negative cases, which is itself the
                // required behaviour.
                let tag = match algorithm.as_str() {
                    "AES-CMAC" => cmac_tag::<Aes>(Aes::new(&key), &msg),
                    "ARIA-CMAC" => cmac_tag::<crown::block::aria::Aria>(
                        crown::block::aria::Aria::new(&key),
                        &msg,
                    ),
                    "CAMELLIA-CMAC" => cmac_tag::<crown::block::camellia::Camellia>(
                        crown::block::camellia::Camellia::new(&key, None),
                        &msg,
                    ),
                    other => panic!("unexpected algorithm {other}"),
                };

                let Some(tag) = tag else {
                    assert!(
                        matches!(t.result, Some(MacTestVectorResult::Invalid) | None),
                        "{file}: {algorithm} accepted key {}",
                        hex::encode(&key)
                    );
                    continue;
                };
                let computed = &tag[..tag_size];

                match t.result {
                    Some(MacTestVectorResult::Valid) => {
                        assert_eq!(
                            hex::encode(computed),
                            hex::encode(&expected),
                            "{file}: {algorithm} tc {}",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Invalid) => {
                        assert_ne!(
                            hex::encode(computed),
                            hex::encode(&expected),
                            "{file}: {algorithm} accepted a bad tag (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 500, "only {checked} CMAC vectors were verified");
}

#[test]
fn test_wycheproof_gmac() {
    let mut checked = 0usize;

    for file in GMAC_TESTS {
        let test = get_mac_with_iv_test(file);

        for group in test.test_groups {
            // crown's GMAC takes the 96-bit GCM IV.
            if group.iv_size != Some(96) || group.tag_size.unwrap_or(128) != 128 {
                continue;
            }

            for t in group.tests {
                let key = hex_to_bytes(&t.key);
                let iv: [u8; 12] = hex_to_bytes(&t.iv).try_into().unwrap();
                let msg = hex_to_bytes(&t.msg);
                let expected = hex_to_bytes(&t.tag);

                let Ok(cipher) = Aes::new(&key) else {
                    assert!(matches!(
                        t.result,
                        Some(MacWithIvTestVectorResult::Invalid)
                    ));
                    continue;
                };
                let mut mac = Gmac::new(cipher, &iv).unwrap();
                mac.write(&msg);
                let tag = mac.sum();

                match t.result {
                    Some(MacWithIvTestVectorResult::Valid) => {
                        assert_eq!(
                            hex::encode(tag),
                            hex::encode(&expected),
                            "{file}: GMAC tc {}",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacWithIvTestVectorResult::Invalid) => {
                        assert_ne!(
                            hex::encode(tag),
                            hex::encode(&expected),
                            "{file}: GMAC accepted a bad tag (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacWithIvTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 200, "only {checked} GMAC vectors were verified");
}

#[test]
fn test_wycheproof_kmac() {
    let mut checked = 0usize;

    for file in KMAC_TESTS {
        let test = get_mac_test(file);
        let algorithm = test.algorithm.unwrap_or_default();

        for group in test.test_groups {
            let tag_size = group.tag_size.unwrap_or(256) as usize / 8;

            for t in group.tests {
                let key = hex_to_bytes(&t.key);
                let msg = hex_to_bytes(&t.msg);
                let expected = hex_to_bytes(&t.tag);

                let mut out = match algorithm.as_str() {
                    "KMAC128" => {
                        let mut mac = Kmac128::new(&key, b"")
                            .unwrap_or_else(|_| panic!("{file}: {algorithm} key rejected"));
                        mac.write(&msg);
                        let mut out = vec![0u8; tag_size];
                        mac.sum(&mut out);
                        out
                    }
                    "KMAC256" => {
                        let mut mac = Kmac256::new(&key, b"")
                            .unwrap_or_else(|_| panic!("{file}: {algorithm} key rejected"));
                        mac.write(&msg);
                        let mut out = vec![0u8; tag_size];
                        mac.sum(&mut out);
                        out
                    }
                    other => panic!("unexpected algorithm {other}"),
                };
                out.truncate(tag_size);

                match t.result {
                    Some(MacTestVectorResult::Valid) => {
                        assert_eq!(
                            hex::encode(&out),
                            hex::encode(&expected),
                            "{file}: {algorithm} tc {}",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Invalid) => {
                        assert_ne!(
                            hex::encode(&out),
                            hex::encode(&expected),
                            "{file}: {algorithm} accepted a bad tag (tc {})",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 100, "only {checked} KMAC vectors were verified");
}

#[test]
fn test_wycheproof_siphash() {
    let mut checked = 0usize;

    for file in SIPHASH_TESTS {
        let test = get_mac_test(file);
        let algorithm = test.algorithm.unwrap_or_default();

        for group in test.test_groups {
            let tag_size = group.tag_size.unwrap_or(64) as usize / 8;

            for t in group.tests {
                let key: [u8; 16] = hex_to_bytes(&t.key).try_into().unwrap();
                let msg = hex_to_bytes(&t.msg);
                let expected = hex_to_bytes(&t.tag);

                let tag = match (algorithm.as_str(), tag_size) {
                    ("SipHash-2-4", 8) => siphash::sum(&msg, &key).to_vec(),
                    ("SipHashX-2-4", 16) => siphash::sum128(&msg, &key).to_vec(),
                    (alg, size) => panic!("unexpected {alg} with a {size}-byte tag"),
                };

                match t.result {
                    Some(MacTestVectorResult::Valid) => {
                        assert_eq!(
                            hex::encode(&tag),
                            hex::encode(&expected),
                            "{file}: {algorithm} tc {}",
                            t.tc_id.unwrap_or_default()
                        );
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Invalid) => {
                        assert_ne!(
                            hex::encode(&tag),
                            hex::encode(&expected),
                            "{file}: {algorithm} accepted a bad tag"
                        );
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked >= 80, "only {checked} SipHash vectors were verified");
}

/// HMAC variants that only exist as wycheproof v1 files.
#[test]
fn test_wycheproof_hmac_extra() {
    use crown::core::CoreWrite;
    use crown::envelope::EvpHash;
    use crown::mac::hmac;

    let mut checked = 0usize;

    for file in HMAC_EXTRA_TESTS {
        let test = get_mac_test(file);
        let algorithm = test.algorithm.unwrap_or_default().replace("HMAC", "");

        for group in test.test_groups {
            let tag_size = group.tag_size.unwrap_or(0) as usize / 8;

            for t in group.tests {
                let key = hex_to_bytes(&t.key);
                let msg = hex_to_bytes(&t.msg);
                let expected = hex_to_bytes(&t.tag);

                let mut h = match algorithm.as_str() {
                    "SHA512/224" => EvpHash::new_sha512_224_hmac(&key),
                    "SHA512/256" => EvpHash::new_sha512_256_hmac(&key),
                    "SM3" => EvpHash::new_sm3_hmac(&key),
                    other => panic!("unexpected algorithm {other}"),
                }
                .unwrap();
                if tag_size != h.size() {
                    continue;
                }
                h.write_all(&msg).unwrap();
                let tag = h.sum();

                match t.result {
                    Some(MacTestVectorResult::Valid) => {
                        assert!(hmac::equal(&tag, &expected), "{file}: {algorithm}");
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Invalid) => {
                        assert!(!hmac::equal(&tag, &expected), "{file}: {algorithm}");
                        checked += 1;
                    }
                    Some(MacTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 200, "only {checked} HMAC vectors were verified");
}

#[test]
fn test_pyca_cmac() {
    let mut checked = 0usize;

    for (file, tripledes) in [
        ("CMAC/nist-800-38b-aes128.txt", false),
        ("CMAC/nist-800-38b-aes192.txt", false),
        ("CMAC/nist-800-38b-aes256.txt", false),
        ("CMAC/nist-800-38b-3des.txt", true),
    ] {
        for v in parse_vectors(&read_pyca(file)) {
            let Some(key) = v
                .concat(&["key"])
                .or_else(|| v.concat(&["key1", "key2", "key3"]))
            else {
                continue;
            };
            let (Some(message), Some(output)) = (v.field(&["message"]), v.field(&["output"]))
            else {
                continue;
            };

            let tag = if tripledes {
                let cipher = crown::block::des::TripleDes::new(&key).unwrap();
                let mut mac = CmacMac::<_, 8>::new(cipher).unwrap();
                mac.write(message);
                mac.sum().to_vec()
            } else {
                let cipher = Aes::new(&key).unwrap();
                let mut mac = CmacMac::<_, 16>::new(cipher).unwrap();
                mac.write(message);
                mac.sum().to_vec()
            };

            assert_eq!(
                hex::encode(&tag),
                hex::encode(output),
                "{file}: CMAC key {}",
                hex::encode(&key)
            );
            checked += 1;
        }
    }

    assert!(checked > 15, "only {checked} CMAC vectors were verified");
}

#[test]
fn test_pyca_poly1305() {
    use crown::mac::poly1305;

    let mut checked = 0usize;
    for v in parse_vectors(&read_pyca("poly1305/rfc7539.txt")) {
        let (Some(key), Some(msg), Some(tag)) = (
            v.field(&["key"]),
            v.field(&["msg"]),
            v.field(&["tag"]),
        ) else {
            continue;
        };
        let key: [u8; 32] = key.try_into().unwrap();

        assert_eq!(
            hex::encode(poly1305::sum(msg, &key)),
            hex::encode(tag),
            "poly1305: key {} msg {}",
            hex::encode(key),
            hex::encode(msg)
        );
        assert!(poly1305::verify(
            &tag.try_into().unwrap(),
            msg,
            &key
        ));
        checked += 1;
    }

    assert!(checked > 10, "only {checked} Poly1305 vectors were verified");
}
