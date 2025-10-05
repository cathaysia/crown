use kittycrypto::{
    core::CoreWrite, envelope::EvpHash, error::CryptoResult, hash::HashUser, mac::hmac,
};

use crate::wycheproof::mac::{MacTestFile, MacTestGroup, MacTestVector};

mod wycheproof;

#[test]
fn test_wycheproof_hmac_test() {
    let builder = |alg: &str, key: &[u8]| -> Option<EvpHash> {
        match alg {
            "SHA224" => EvpHash::new_sha224_hmac(key),
            "SHA256" => EvpHash::new_sha256_hmac(key),
            "SHA384" => EvpHash::new_sha384_hmac(key),
            "SHA3-224" => EvpHash::new_sha3_224_hmac(key),
            "SHA3-256" => EvpHash::new_sha3_256_hmac(key),
            "SHA3-384" => EvpHash::new_sha3_384_hmac(key),
            "SHA3-512" => EvpHash::new_sha3_512_hmac(key),
            "SHA512" => EvpHash::new_sha512_hmac(key),
            _ => return None,
        }
        .ok()
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

#[test]
fn test_pyca_hmac_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/HMAC";
    let files: [(&str, fn(&[u8]) -> CryptoResult<EvpHash>); 6] = [
        ("rfc-2202-md5.txt", EvpHash::new_md5_hmac),
        ("rfc-2202-sha1.txt", EvpHash::new_sha1_hmac),
        // "rfc-2286-ripemd160.txt",
        ("rfc-4231-sha224.txt", EvpHash::new_sha224_hmac),
        ("rfc-4231-sha256.txt", EvpHash::new_sha256_hmac),
        ("rfc-4231-sha384.txt", EvpHash::new_sha384_hmac),
        ("rfc-4231-sha512.txt", EvpHash::new_sha512_hmac),
    ];

    for (filename, hmac_constructor) in files {
        let content = std::fs::read_to_string(format!("{BASE_DIR}/{filename}")).unwrap();
        let mut lines = content.lines();

        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("Len = ") {
                let mut key = None;
                let mut msg = None;
                let mut expected_md = None;

                for line in lines.by_ref() {
                    let line = line.trim();
                    if line.is_empty() {
                        break;
                    }
                    if line.starts_with('#') {
                        continue;
                    }

                    if let Some(key_hex) = line.strip_prefix("Key = ") {
                        key = Some(hex::decode(key_hex).unwrap());
                    } else if let Some(msg_hex) = line.strip_prefix("Msg = ") {
                        msg = Some(hex::decode(msg_hex).unwrap());
                    } else if let Some(md_hex) = line.strip_prefix("MD = ") {
                        expected_md = Some(hex::decode(md_hex).unwrap());
                    }
                }

                if let (Some(key), Some(msg), Some(expected_md)) = (key, msg, expected_md) {
                    let mut hmac = hmac_constructor(&key).unwrap();
                    hmac.write_all(&msg).unwrap();
                    let result = hmac.sum();

                    assert_eq!(
                        result,
                        expected_md,
                        "HMAC test failed for {}: expected {}, got {}",
                        filename,
                        hex::encode(&expected_md),
                        hex::encode(&result)
                    );
                }
            }
        }
    }
}
