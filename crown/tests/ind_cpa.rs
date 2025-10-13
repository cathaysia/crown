mod wycheproof;

use crown::envelope::EvpBlockCipher;
use wycheproof::ind_cpa::*;

#[test]
fn test_ind_cpa() {
    let builder = |alg: &str, key: &[u8], iv: &[u8]| -> Option<EvpBlockCipher> {
        Some(
            match alg {
                "AES-CBC-PKCS5" => EvpBlockCipher::new_aes_cbc(key, iv),
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

                let mut out = hex::decode(t.msg.as_ref().unwrap()).unwrap();
                h.encrypt_alloc(&mut out)
                    .unwrap_or_else(|_| panic!("test: {idx} failed."));

                let is_valid = matches!(t.result.unwrap(), IndCpaTestVectorResult::Valid);
                if !is_valid {
                    continue;
                }

                assert_eq!(
                    &hex::encode(&out),
                    t.ct.as_ref().unwrap(),
                    "test: {idx} failed. expected: {:?}, got: {:?}, {}",
                    t.ct.as_ref().unwrap(),
                    &hex::encode(&out),
                    t.comment.as_ref().unwrap()
                );

                h.decrypt_alloc(&mut out).unwrap();
                assert_eq!(&hex::encode(out), t.msg.as_ref().unwrap());
            }
        }
    }
}
