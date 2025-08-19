mod wycheproof;

use std::io::Read;

use wycheproof::hkdf::*;

#[test]
fn test_hkdf() {
    let builder = |alg: &str, secret: &[u8], salt: &[u8], info: &[u8]| -> Option<Box<dyn Read>> {
        Some(match alg {
            "SHA-1" => Box::new(kittycrypto::hkdf::new(
                kittycrypto::sha1::new,
                secret,
                salt,
                info,
            )),
            "SHA-256" => Box::new(kittycrypto::hkdf::new(
                kittycrypto::sha256::new,
                secret,
                salt,
                info,
            )),
            "SHA-384" => Box::new(kittycrypto::hkdf::new(
                kittycrypto::sha512::new384,
                secret,
                salt,
                info,
            )),
            "SHA-512" => Box::new(kittycrypto::hkdf::new(
                kittycrypto::sha512::new512,
                secret,
                salt,
                info,
            )),
            _ => return None,
        })
    };

    for file in HMAC_TESTS {
        let test = get_hkdf_test(file);
        let algorithm = test.algorithm.unwrap().replace("HKDF-", "");

        for g in test.test_groups {
            for t in g.tests {
                let mut h = builder(
                    &algorithm,
                    &hex::decode(t.ikm.unwrap()).unwrap(),
                    &hex::decode(t.salt.unwrap()).unwrap(),
                    &hex::decode(t.info.unwrap()).unwrap(),
                )
                .unwrap();

                let mut key = vec![0; t.size.unwrap() as usize];

                if h.read_exact(&mut key).is_err() {
                    continue;
                }

                let res = key == hex::decode(t.okm.unwrap()).unwrap();

                match t.result.unwrap() {
                    HkdfTestVectorResult::Valid => {
                        assert!(res);
                    }
                    HkdfTestVectorResult::Invalid => {
                        assert!(!res);
                    }
                    HkdfTestVectorResult::Acceptable => todo!(),
                }
            }
        }
    }
}
