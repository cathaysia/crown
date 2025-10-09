use crown::{core::CoreWrite, envelope::EvpHash, error::CryptoResult};

#[test]
fn test_pyca_hash_vectors() {
    const BASE_DIR: &str = "tests/cryptography/vectors/cryptography_vectors/hashes";
    #[allow(clippy::type_complexity)]
    const FILES: [(&str, fn() -> CryptoResult<EvpHash>); 40] = [
        ("MD5/rfc-1321.txt", EvpHash::new_md5),
        ("SHA1/SHA1LongMsg.rsp", EvpHash::new_sha1),
        ("SHA1/SHA1Monte.rsp", EvpHash::new_sha1),
        ("SHA1/SHA1ShortMsg.rsp", EvpHash::new_sha1),
        ("SHA2/SHA224LongMsg.rsp", EvpHash::new_sha224),
        ("SHA2/SHA224Monte.rsp", EvpHash::new_sha224),
        ("SHA2/SHA224ShortMsg.rsp", EvpHash::new_sha224),
        ("SHA2/SHA256LongMsg.rsp", EvpHash::new_sha256),
        ("SHA2/SHA256Monte.rsp", EvpHash::new_sha256),
        ("SHA2/SHA256ShortMsg.rsp", EvpHash::new_sha256),
        ("SHA2/SHA384LongMsg.rsp", EvpHash::new_sha384),
        ("SHA2/SHA384Monte.rsp", EvpHash::new_sha384),
        ("SHA2/SHA384ShortMsg.rsp", EvpHash::new_sha384),
        ("SHA2/SHA512LongMsg.rsp", EvpHash::new_sha512),
        ("SHA2/SHA512Monte.rsp", EvpHash::new_sha512),
        ("SHA2/SHA512ShortMsg.rsp", EvpHash::new_sha512),
        ("SHA2/SHA512_224LongMsg.rsp", EvpHash::new_sha512_224),
        ("SHA2/SHA512_224Monte.rsp", EvpHash::new_sha512_224),
        ("SHA2/SHA512_224ShortMsg.rsp", EvpHash::new_sha512_224),
        ("SHA2/SHA512_256LongMsg.rsp", EvpHash::new_sha512_256),
        ("SHA2/SHA512_256Monte.rsp", EvpHash::new_sha512_256),
        ("SHA2/SHA512_256ShortMsg.rsp", EvpHash::new_sha512_256),
        ("SHA3/SHA3_224LongMsg.rsp", EvpHash::new_sha3_224),
        ("SHA3/SHA3_224Monte.rsp", EvpHash::new_sha3_224),
        ("SHA3/SHA3_224ShortMsg.rsp", EvpHash::new_sha3_224),
        ("SHA3/SHA3_256LongMsg.rsp", EvpHash::new_sha3_256),
        ("SHA3/SHA3_256Monte.rsp", EvpHash::new_sha3_256),
        ("SHA3/SHA3_256ShortMsg.rsp", EvpHash::new_sha3_256),
        ("SHA3/SHA3_384LongMsg.rsp", EvpHash::new_sha3_384),
        ("SHA3/SHA3_384Monte.rsp", EvpHash::new_sha3_384),
        ("SHA3/SHA3_384ShortMsg.rsp", EvpHash::new_sha3_384),
        ("SHA3/SHA3_512LongMsg.rsp", EvpHash::new_sha3_512),
        ("SHA3/SHA3_512Monte.rsp", EvpHash::new_sha3_512),
        ("SHA3/SHA3_512ShortMsg.rsp", EvpHash::new_sha3_512),
        ("SHAKE/SHAKE128LongMsg.rsp", EvpHash::new_shake128),
        ("SHAKE/SHAKE128Monte.rsp", EvpHash::new_shake128),
        ("SHAKE/SHAKE128ShortMsg.rsp", EvpHash::new_shake128),
        // ("SHAKE/SHAKE128VariableOut.rsp", EvpHash::new_shake128),
        ("SHAKE/SHAKE256LongMsg.rsp", EvpHash::new_shake256),
        ("SHAKE/SHAKE256Monte.rsp", EvpHash::new_shake256),
        ("SHAKE/SHAKE256ShortMsg.rsp", EvpHash::new_shake256),
        // // ("SHAKE/SHAKE256VariableOut.rsp", EvpHash::new_shake128),
        // ("blake2/blake2b.txt", EvpHash::new_blake2b),
        // ("blake2/blake2s.txt", EvpHash::new_blake2s),
    ];

    for (filename, hash_constructor) in FILES {
        let content = std::fs::read_to_string(format!("{BASE_DIR}/{filename}")).unwrap();
        let mut lines = content.lines();

        while let Some(line) = lines.next() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("Len = ") {
                let len_str = line.strip_prefix("Len = ").unwrap();
                let len = len_str.parse::<usize>().unwrap();
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

                    if let Some(msg_hex) = line.strip_prefix("Msg = ") {
                        if len == 0 {
                            msg = Some(Vec::new());
                        } else {
                            let decoded = hex::decode(msg_hex).unwrap();
                            // Verify the decoded length matches the expected bit length
                            if decoded.len() * 8 == len {
                                msg = Some(decoded);
                            } else {
                                panic!(
                                    "Message length mismatch: expected {} bits, got {} bytes",
                                    len,
                                    decoded.len()
                                );
                            }
                        }
                    } else if let Some(md_hex) = line.strip_prefix("MD = ") {
                        expected_md = Some(hex::decode(md_hex).unwrap());
                    }
                }

                if let (Some(msg), Some(expected_md)) = (msg, expected_md) {
                    let mut hash = hash_constructor().unwrap();
                    hash.write_all(&msg).unwrap();
                    let result = hash.sum();

                    assert_eq!(
                        result,
                        expected_md,
                        "hash test failed for {}: expected {}, got {}",
                        filename,
                        hex::encode(&expected_md),
                        hex::encode(&result)
                    );
                }
            }
        }
    }
}
