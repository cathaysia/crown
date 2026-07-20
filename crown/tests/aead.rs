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
                let expected_tag = hex::decode(t.tag.as_ref().unwrap()).unwrap();
                let is_valid = matches!(t.result.unwrap(), AeadTestVectorResult::Valid);

                let Some(h) = builder(&algorithm, &key, nonce.len(), expected_tag.len()) else {
                    assert!(!is_valid, "test: {idx} failed.");
                    continue;
                };

                let mut out = hex::decode(t.msg.as_ref().unwrap()).unwrap();
                if nonce.len() != h.nonce_size() {
                    continue;
                }
                let tag = h
                    .seal_in_place_separate_tag(&mut out, &nonce, &aad)
                    .unwrap_or_else(|err| panic!("{algorithm} test {idx} failed: {err:?}"));

                assert_eq!(
                    &hex::encode(&out),
                    t.ct.as_ref().unwrap(),
                    "test: {idx} failed. expected: {:?}, got: {:?}, {}",
                    t.ct.as_ref().unwrap(),
                    &hex::encode(&out),
                    t.comment.as_ref().unwrap()
                );
                assert_eq!(&hex::encode(&tag) == t.tag.as_ref().unwrap(), is_valid);

                if !is_valid {
                    let mut invalid_ct = hex::decode(t.ct.as_ref().unwrap()).unwrap();
                    assert!(
                        h.open_in_place_separate_tag(&mut invalid_ct, &expected_tag, &nonce, &aad)
                            .is_err(),
                        "test: {idx} failed."
                    );
                    continue;
                }

                h.open_in_place_separate_tag(&mut out, &tag, &nonce, &aad)
                    .unwrap();
                assert_eq!(&hex::encode(out), t.msg.as_ref().unwrap());
            }
        }
    }
}

enum CcmCipher {
    Aes,
    Aria,
    Camellia,
    Sm4,
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
    }
}
