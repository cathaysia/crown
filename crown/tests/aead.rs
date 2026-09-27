mod wycheproof;

use crown::envelope::EvpAeadCipher;
use wycheproof::aead::*;

#[test]
fn test_aead() {
    let builder =
        |alg: &str, key: &[u8], nonce_len: usize, tag_len: usize| -> Option<EvpAeadCipher> {
            Some(
                match alg {
                    "CHACHA20-POLY1305" => EvpAeadCipher::new_chacha20_poly1305(key),
                    "XCHACHA20-POLY1305" => EvpAeadCipher::new_xchacha20_poly1305(key),
                    "AES-GCM" => EvpAeadCipher::new_aes_gcm(key),
                    "AES-EAX" => {
                        if nonce_len < 12 || tag_len != 16 {
                            return None;
                        }
                        EvpAeadCipher::new_aes_eax::<16>(key, nonce_len)
                    }
                    "AES-CCM" => return build_ccm(CcmCipher::Aes, key, nonce_len, tag_len),
                    "ARIA-GCM" => EvpAeadCipher::new_aria_gcm(key),
                    "ARIA-CCM" => return build_ccm(CcmCipher::Aria, key, nonce_len, tag_len),
                    "CAMELLIA-CCM" => {
                        return build_ccm(CcmCipher::Camellia, key, nonce_len, tag_len);
                    }
                    "SM4-CCM" => return build_ccm(CcmCipher::Sm4, key, nonce_len, tag_len),
                    "SM4-GCM" => EvpAeadCipher::new_sm4_gcm(key),
                    "SEED-GCM" => EvpAeadCipher::new_kseed_gcm(key),
                    "SEED-CCM" => return build_ccm(CcmCipher::Kseed, key, nonce_len, tag_len),
                    _ => return None,
                }
                .unwrap(),
            )
        };

    for file in AEAD_TESTS {
        let test = get_aead_test(file);
        let algorithm = test.algorithm.unwrap().replace("HKDF-", "");

        for g in test.test_groups {
            for (idx, t) in g.tests.iter().enumerate() {
                let key = hex::decode(t.key.as_ref().unwrap()).unwrap();
                let nonce = hex::decode(t.iv.as_ref().unwrap()).unwrap();
                let aad = hex::decode(t.aad.as_ref().unwrap()).unwrap();
                let expected_tag = hex::decode(t.tag.as_deref().unwrap()).unwrap();
                let is_valid = matches!(t.result.unwrap(), AeadTestVectorResult::Valid);

                let Some(h) = builder(&algorithm, &key, nonce.len(), expected_tag.len()) else {
                    assert!(!is_valid, "test: {idx} failed.");
                    continue;
                };

                let mut out = hex::decode(t.msg.as_deref().unwrap()).unwrap();
                if nonce.len() != h.nonce_size() {
                    continue;
                }
                let tag = h
                    .seal_in_place_separate_tag(&mut out, &nonce, &aad)
                    .unwrap_or_else(|err| panic!("{algorithm} test {idx} failed: {err:?}"));

                assert_eq!(
                    hex::encode(&out),
                    t.ct.as_deref().unwrap(),
                    "test: {idx} failed. expected: {:?}, got: {:?}, {}",
                    t.ct.as_deref().unwrap(),
                    hex::encode(&out),
                    t.comment.as_ref().unwrap()
                );
                assert_eq!(hex::encode(&tag) == t.tag.as_deref().unwrap(), is_valid);

                if !is_valid {
                    let mut invalid_ct = hex::decode(t.ct.as_deref().unwrap()).unwrap();
                    assert!(
                        h.open_in_place_separate_tag(&mut invalid_ct, &expected_tag, &nonce, &aad)
                            .is_err(),
                        "test: {idx} failed."
                    );
                    continue;
                }

                h.open_in_place_separate_tag(&mut out, &tag, &nonce, &aad)
                    .unwrap();
                assert_eq!(&hex::encode(out), t.msg.as_deref().unwrap());
            }
        }
    }
}

enum CcmCipher {
    Aes,
    Aria,
    Camellia,
    Sm4,
    Kseed,
}

fn build_ccm(
    cipher: CcmCipher,
    key: &[u8],
    nonce_len: usize,
    tag_len: usize,
) -> Option<EvpAeadCipher> {
    macro_rules! build_with_nonce {
        ($tag_size:literal) => {
            match nonce_len {
                7 => build_ccm_with_params::<$tag_size, 7>(&cipher, key),
                8 => build_ccm_with_params::<$tag_size, 8>(&cipher, key),
                9 => build_ccm_with_params::<$tag_size, 9>(&cipher, key),
                10 => build_ccm_with_params::<$tag_size, 10>(&cipher, key),
                11 => build_ccm_with_params::<$tag_size, 11>(&cipher, key),
                12 => build_ccm_with_params::<$tag_size, 12>(&cipher, key),
                13 => build_ccm_with_params::<$tag_size, 13>(&cipher, key),
                _ => return None,
            }
        };
    }

    Some(
        match tag_len {
            4 => build_with_nonce!(4),
            6 => build_with_nonce!(6),
            8 => build_with_nonce!(8),
            10 => build_with_nonce!(10),
            12 => build_with_nonce!(12),
            14 => build_with_nonce!(14),
            16 => build_with_nonce!(16),
            _ => return None,
        }
        .unwrap(),
    )
}

fn build_ccm_with_params<const TAG_SIZE: usize, const NONCE_SIZE: usize>(
    cipher: &CcmCipher,
    key: &[u8],
) -> crown::error::CryptoResult<EvpAeadCipher> {
    match cipher {
        CcmCipher::Aes => EvpAeadCipher::new_aes_ccm::<TAG_SIZE, NONCE_SIZE>(key),
        CcmCipher::Aria => EvpAeadCipher::new_aria_ccm::<TAG_SIZE, NONCE_SIZE>(key),
        CcmCipher::Camellia => EvpAeadCipher::new_camellia_ccm::<TAG_SIZE, NONCE_SIZE>(key, None),
        CcmCipher::Sm4 => EvpAeadCipher::new_sm4_ccm::<TAG_SIZE, NONCE_SIZE>(key),
        CcmCipher::Kseed => EvpAeadCipher::new_kseed_ccm::<TAG_SIZE, NONCE_SIZE>(key),
    }
}

/// AES-SIV from wycheproof: the `DaeadTest` groups carry `ct` as the tag
/// followed by the ciphertext, the AEAD-shaped ones keep the tag separate and
/// use the nonce as the final AAD element.
#[test]
fn test_wycheproof_siv() {
    use crown::aead::siv::AesSiv;

    let mut checked = 0usize;
    let mut rejected = 0usize;
    for file in SIV_TESTS {
        let test = get_aead_test(file);

        for g in test.test_groups {
            for (idx, t) in g.tests.iter().enumerate() {
                let key = hex::decode(t.key.as_ref().unwrap()).unwrap();
                let aad = hex::decode(t.aad.as_deref().unwrap_or_default()).unwrap();
                let msg = hex::decode(t.msg.as_deref().unwrap()).unwrap();
                let ct = hex::decode(t.ct.as_deref().unwrap()).unwrap();

                // The nonce, when present, is the last AAD element.
                let nonce = t.iv.as_deref().map(|iv| hex::decode(iv).unwrap());
                let mut aads: Vec<&[u8]> = vec![&aad];
                if let Some(nonce) = &nonce {
                    aads.push(nonce);
                }

                let Ok(mut siv) = AesSiv::new(&key) else {
                    // Unsupported key size for this vector.
                    continue;
                };
                let tag = t.tag.as_deref().map(|tag| hex::decode(tag).unwrap());

                // `(expected tag, expected ciphertext)`, the tag being the
                // prefix of `ct` in the DAEAD shape.
                let (expected_tag, expected_ct) = match &tag {
                    Some(tag) => (tag.clone(), ct.clone()),
                    None => (ct[..16].to_vec(), ct[16..].to_vec()),
                };

                let mut buf = msg.clone();
                let computed_tag = siv.seal_in_place(&mut buf, &aads).unwrap();

                match t.result {
                    Some(AeadTestVectorResult::Valid) => {
                        assert_eq!(
                            hex::encode(computed_tag),
                            hex::encode(&expected_tag),
                            "{file} tc {idx} tag"
                        );
                        assert_eq!(
                            hex::encode(&buf),
                            hex::encode(&expected_ct),
                            "{file} tc {idx} ct"
                        );

                        let mut buf = expected_ct.clone();
                        siv.open_in_place(&mut buf, &expected_tag, &aads).unwrap();
                        assert_eq!(hex::encode(&buf), hex::encode(&msg), "{file} tc {idx} open");
                        checked += 1;
                    }
                    Some(AeadTestVectorResult::Invalid) => {
                        let mut buf = expected_ct.clone();
                        assert!(
                            siv.open_in_place(&mut buf, &expected_tag, &aads).is_err(),
                            "{file}: invalid SIV vector accepted (tc {idx})"
                        );
                        rejected += 1;
                    }
                    Some(AeadTestVectorResult::Acceptable) | None => {}
                }
            }
        }
    }

    assert!(checked > 100, "only {checked} SIV vectors were verified");
    assert!(
        rejected > 10,
        "only {rejected} negative SIV vectors were rejected"
    );
}
