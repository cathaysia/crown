mod wycheproof;

use crown::envelope::EvpBlockCipher;
use wycheproof::ind_cpa::*;

#[test]
fn test_ind_cpa() {
    let builder = |alg: &str, key: &[u8], iv: &[u8]| -> Option<EvpBlockCipher> {
        Some(
            match alg {
                "AES-CBC-PKCS5" => EvpBlockCipher::new_aes_cbc(key, iv),
                "ARIA-CBC-PKCS5" => EvpBlockCipher::new_aria_cbc(key, iv),
                _ => return None,
            }
            .unwrap(),
        )
    };

    for file in IND_CPA_TESTS {
        let test = get_ind_cpa_test(file);
        let algorithm = test.algorithm.unwrap().replace("HKDF-", "");

        for g in test.test_groups {
            for (idx, t) in g.tests.iter().enumerate() {
                let mut h = builder(
                    &algorithm,
                    &hex::decode(t.key.as_ref().unwrap()).unwrap(),
                    &hex::decode(t.iv.as_ref().unwrap()).unwrap(),
                )
                .unwrap();

                let mut out = hex::decode(t.msg.as_deref().unwrap()).unwrap();
                h.encrypt_alloc(&mut out)
                    .unwrap_or_else(|_| panic!("test: {idx} failed."));

                let is_valid = matches!(t.result.unwrap(), IndCpaTestVectorResult::Valid);
                if !is_valid {
                    continue;
                }

                assert_eq!(
                    hex::encode(&out),
                    t.ct.as_deref().unwrap(),
                    "test: {idx} failed. expected: {:?}, got: {:?}, {}",
                    t.ct.as_deref().unwrap(),
                    hex::encode(&out),
                    t.comment.as_ref().unwrap()
                );

                h.decrypt_alloc(&mut out).unwrap();
                assert_eq!(&hex::encode(out), t.msg.as_deref().unwrap());
            }
        }
    }
}

/// AES-XTS from wycheproof (`IndCpaTest` shape, the 64-bit `iv` is the data
/// unit tweak, little-endian inside the 128-bit tweak block).
#[test]
fn test_wycheproof_xts() {
    use crown::block::aes::Aes;
    use crown::modes::xts::Xts;

    let mut checked = 0usize;
    for file in XTS_TESTS {
        let test = get_ind_cpa_test(file);

        for g in test.test_groups {
            for (idx, t) in g.tests.iter().enumerate() {
                let key = hex::decode(t.key.as_ref().unwrap()).unwrap();
                let iv = hex::decode(t.iv.as_deref().unwrap_or_default()).unwrap();
                let msg = hex::decode(t.msg.as_deref().unwrap()).unwrap();
                let ct = hex::decode(t.ct.as_deref().unwrap()).unwrap();
                if iv.len() > 16 {
                    continue;
                }

                let mut tweak = [0u8; 16];
                tweak[..iv.len()].copy_from_slice(&iv);

                // Half-key size 24 (AES-192) is not supported by crown's XTS.
                let Ok(cipher) = Xts::<Aes>::new(&key) else {
                    continue;
                };
                let mut buf = msg.clone();
                let encrypted: Option<Vec<u8>> = match cipher.encrypt(&tweak, &mut buf) {
                    Ok(()) => Some(buf),
                    Err(_) => None,
                };

                let is_valid = matches!(t.result.unwrap(), IndCpaTestVectorResult::Valid);
                if is_valid {
                    assert_eq!(
                        hex::encode(encrypted.as_ref().unwrap()),
                        hex::encode(&ct),
                        "{file} tc {idx}"
                    );

                    let mut buf = ct.clone();
                    cipher.decrypt(&tweak, &mut buf).unwrap();
                    assert_eq!(
                        hex::encode(&buf),
                        hex::encode(&msg),
                        "{file} tc {idx} decrypt"
                    );
                } else {
                    assert!(
                        encrypted.as_deref() != Some(ct.as_slice()),
                        "{file}: invalid XTS case accepted (tc {idx})"
                    );
                }
                checked += 1;
            }
        }
    }

    assert!(checked >= 82, "only {checked} XTS vectors were verified");
}
