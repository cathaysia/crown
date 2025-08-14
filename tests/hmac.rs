use std::io::Write;

use kittycrypto::{
    hash::{ErasedHash, HashUser},
    hmac,
};

use crate::wycheproof::mac::{MacTestFile, MacTestGroup, MacTestVector};

mod wycheproof;

#[test]
fn test_wycheproof_hmac_test() {
    let builder = |alg: &str, key: &[u8]| -> Option<ErasedHash> {
        use kittycrypto::hmac;

        Some(match alg {
            "SHA224" => ErasedHash::new(hmac::new(kittycrypto::sha256::new224, key)),
            "SHA256" => ErasedHash::new(hmac::new(kittycrypto::sha256::new, key)),
            "SHA384" => ErasedHash::new(hmac::new(kittycrypto::sha512::new384, key)),
            "SHA3-224" => ErasedHash::new(hmac::new(kittycrypto::sha3::new224, key)),
            "SHA3-256" => ErasedHash::new(hmac::new(kittycrypto::sha3::new256, key)),
            "SHA3-384" => ErasedHash::new(hmac::new(kittycrypto::sha3::new384, key)),
            "SHA3-512" => ErasedHash::new(hmac::new(kittycrypto::sha3::new512, key)),
            "SHA512" => ErasedHash::new(hmac::new(kittycrypto::sha512::new, key)),
            _ => return None,
        })
    };

    for file in wycheproof::mac::HMAC_TESTS {
        let MacTestFile {
            algorithm,
            test_groups,
            ..
        } = wycheproof::mac::get_mac_test(file);
        let algorithm = algorithm.unwrap().replace("HMAC", "");

        for group in test_groups {
            let MacTestGroup {
                tests, tag_size, ..
            } = group;
            let tag_size = tag_size.unwrap() as usize;
            let tag_size = tag_size / 8;

            for test in tests {
                let MacTestVector {
                    comment,
                    key,
                    msg,
                    tag,
                    tc_id,
                    result,
                    ..
                } = test;
                let tc_id = tc_id.unwrap();
                let comment = comment.unwrap();

                let Some(mut h) = builder(&algorithm, &hex::decode(key.unwrap()).unwrap()) else {
                    continue;
                };
                if tag_size != h.size() {
                    continue;
                }

                h.write_all(&hex::decode(msg.unwrap()).unwrap()).unwrap();

                let sum = h.sum();
                let expected = hex::decode(tag.unwrap()).unwrap();
                let equal = hmac::equal(&sum, &expected);
                match result.unwrap() {
                    wycheproof::mac::MacTestVectorResult::Valid => {
                        assert!(
                            equal,
                            "{file} - {algorithm} - {tc_id} failed:\n{comment} - {} - {}",
                            hex::encode(sum),
                            hex::encode(expected)
                        );
                    }
                    wycheproof::mac::MacTestVectorResult::Invalid => {
                        assert!(
                            !equal,
                            "{file} - {algorithm} - {tc_id} failed:\n{comment} - {} - {}",
                            hex::encode(sum),
                            hex::encode(expected)
                        );
                    }
                    wycheproof::mac::MacTestVectorResult::Acceptable => todo!(),
                }
            }
        }
    }
}
