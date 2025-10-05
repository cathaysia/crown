mod wycheproof;

use kittycrypto::envelope::EvpAeadCipher;
use wycheproof::aead::*;

#[test]
fn test_aead() {
    let builder = |alg: &str, key: &[u8]| -> Option<EvpAeadCipher> {
        Some(
            match alg {
                "CHACHA20-POLY1305" => EvpAeadCipher::new_chacha20_poly1305(key),
                "XCHACHA20-POLY1305" => EvpAeadCipher::new_xchacha20_poly1305(key),
                "AES-GCM" => EvpAeadCipher::new_aes_gcm(key),
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
                let h =
                    builder(&algorithm, &hex::decode(t.key.as_ref().unwrap()).unwrap()).unwrap();

                let mut out = hex::decode(t.msg.as_ref().unwrap()).unwrap();
                if hex::decode(t.iv.as_ref().unwrap()).unwrap().len() != h.nonce_size() {
                    continue;
                }
                let tag = h
                    .seal_in_place_separate_tag(
                        &mut out,
                        &hex::decode(t.iv.as_ref().unwrap()).unwrap(),
                        &hex::decode(t.aad.as_ref().unwrap()).unwrap(),
                    )
                    .unwrap_or_else(|_| panic!("test: {idx} failed."));

                let is_valid = matches!(t.result.unwrap(), AeadTestVectorResult::Valid);

                assert_eq!(
                    &hex::encode(&out),
                    t.ct.as_ref().unwrap(),
                    "test: {idx} failed. expected: {:?}, got: {:?}, {}",
                    t.ct.as_ref().unwrap(),
                    &hex::encode(&out),
                    t.comment.as_ref().unwrap()
                );
                assert_eq!(&hex::encode(&tag) == t.tag.as_ref().unwrap(), is_valid);

                h.open_in_place_separate_tag(
                    &mut out,
                    &tag,
                    &hex::decode(t.iv.as_ref().unwrap()).unwrap(),
                    &hex::decode(t.aad.as_ref().unwrap()).unwrap(),
                )
                .unwrap();
                assert_eq!(&hex::encode(out), t.msg.as_ref().unwrap());
            }
        }
    }
}
