use crate::args::ArgsHash;
use kittycrypto::{
    hash::{ErasedHash, HashVariable},
    hmac::HMAC,
};
use rayon::prelude::*;
use std::{collections::BTreeMap, io::Write};

pub fn run_hash(args_hash: ArgsHash) -> anyhow::Result<()> {
    let ArgsHash {
        algorithm,
        files,
        hmac,
        key,
        length,
        ..
    } = args_hash;

    #[cfg(feature = "cuda")]
    if algorithm.is_cuda() {
        cuda::calc_and_output_hash(algorithm, files);
        return Ok(());
    }
    let key = if hmac {
        key.map(|v| hex::decode(&v).unwrap())
    } else {
        None
    };
    if hmac && key.is_none() {
        panic!("use HMAC but not provided a key.")
    }

    match algorithm {
        crate::args::HashAlgorithm::Blake2bVariable
        | crate::args::HashAlgorithm::Blake2sVariable => {
            calc_and_output_hash_variable(
                &algorithm.to_string(),
                files,
                hmac,
                key.as_deref(),
                length,
            );
        }
        _ => {
            calc_and_output_hash(&algorithm.to_string(), files, hmac, key.as_deref());
        }
    }

    Ok(())
}

pub fn create_hash_from_str(hash: &str, use_hmac: bool, key: Option<&[u8]>) -> Option<ErasedHash> {
    if !use_hmac {
        Some(match hash {
            "md4" | "md4sum" => ErasedHash::new(kittycrypto::md4::new_md4()),
            "md5" | "md5sum" => ErasedHash::new(kittycrypto::md5::new_md5()),
            "sha1" => ErasedHash::new(kittycrypto::sha1::new()),
            "sha224" => ErasedHash::new(kittycrypto::sha256::new224()),
            "sha256" => ErasedHash::new(kittycrypto::sha256::new256()),
            "sha384" => ErasedHash::new(kittycrypto::sha512::new384()),
            "sha512" => ErasedHash::new(kittycrypto::sha512::new512()),
            "sha512-224" => ErasedHash::new(kittycrypto::sha512::new512_224()),
            "sha512-256" => ErasedHash::new(kittycrypto::sha512::new512_256()),
            "sha3-224" => ErasedHash::new(kittycrypto::sha3::new224()),
            "sha3-256" => ErasedHash::new(kittycrypto::sha3::new256()),
            "sha3-384" => ErasedHash::new(kittycrypto::sha3::new384()),
            "sha3-512" => ErasedHash::new(kittycrypto::sha3::new512()),
            "blake2b-256" => {
                ErasedHash::new(kittycrypto::blake2b::new256(None).expect("create blake2b failed"))
            }
            "blake2b-384" => {
                ErasedHash::new(kittycrypto::blake2b::new384(None).expect("create blake2b failed"))
            }
            "blake2b-512" => {
                ErasedHash::new(kittycrypto::blake2b::new512(None).expect("create blake2b failed"))
            }
            "blake2s-128" => {
                ErasedHash::new(kittycrypto::blake2s::new128(None).expect("create blake2s failed"))
            }
            "blake2s-256" => {
                ErasedHash::new(kittycrypto::blake2s::new256(None).expect("create blake2s failed"))
            }
            "blake2s" => ErasedHash::new(kittycrypto::sha3::new512()),
            _ => return None,
        })
    } else {
        let key = key.expect("use HMAC but not provided a key.");
        Some(match hash {
            "md4" | "md4sum" => ErasedHash::new(HMAC::new(kittycrypto::md4::new_md4, key)),
            "md5" | "md5sum" => ErasedHash::new(HMAC::new(kittycrypto::md5::new_md5, key)),
            "sha1" => ErasedHash::new(HMAC::new(kittycrypto::sha1::new, key)),
            "sha224" => ErasedHash::new(HMAC::new(kittycrypto::sha256::new224, key)),
            "sha256" => ErasedHash::new(HMAC::new(kittycrypto::sha256::new256, key)),
            "sha384" => ErasedHash::new(HMAC::new(kittycrypto::sha512::new384, key)),
            "sha512" => ErasedHash::new(HMAC::new(kittycrypto::sha512::new512, key)),
            "sha512-224" => ErasedHash::new(HMAC::new(kittycrypto::sha512::new512_224, key)),
            "sha512-256" => ErasedHash::new(HMAC::new(kittycrypto::sha512::new512_256, key)),
            "sha3-224" => ErasedHash::new(HMAC::new(kittycrypto::sha3::new224, key)),
            "sha3-256" => ErasedHash::new(HMAC::new(kittycrypto::sha3::new256, key)),
            "sha3-384" => ErasedHash::new(HMAC::new(kittycrypto::sha3::new384, key)),
            "sha3-512" => ErasedHash::new(HMAC::new(kittycrypto::sha3::new512, key)),
            "blake2b-256" => ErasedHash::new(
                kittycrypto::blake2b::new256(Some(key)).expect("create blake2b failed"),
            ),
            "blake2b-384" => ErasedHash::new(
                kittycrypto::blake2b::new384(Some(key)).expect("create blake2b failed"),
            ),
            "blake2b-512" => ErasedHash::new(
                kittycrypto::blake2b::new512(Some(key)).expect("create blake2b failed"),
            ),
            "blake2s-128" => ErasedHash::new(
                kittycrypto::blake2s::new128(Some(key)).expect("create blake2s failed"),
            ),
            "blake2s-256" => ErasedHash::new(
                kittycrypto::blake2s::new256(Some(key)).expect("create blake2s failed"),
            ),
            _ => return None,
        })
    }
}

pub(crate) fn calc_and_output_hash(
    algorithm: &str,
    files: Vec<String>,
    use_hmac: bool,
    key: Option<&[u8]>,
) {
    rayon::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        s.spawn(move |_| {
            files
                .into_iter()
                .enumerate()
                .par_bridge()
                .for_each(|(i, path)| {
                    let content = std::fs::read(&path).unwrap();
                    let mut hasher = create_hash_from_str(algorithm, use_hmac, key)
                        .unwrap_or_else(|| panic!("unknown hash algorithm: {algorithm}"));

                    hasher.write_all(&content).unwrap();
                    let sum = hasher.sum();
                    tx.send((i, path, hex::encode(sum))).unwrap();
                });
        });

        let mut buffer = BTreeMap::new();
        let mut expected = 0;
        while let Ok((i, path, hex)) = rx.recv() {
            buffer.insert(i, (path, hex));
            if i <= expected {
                expected += 1;
                for (_, (path, hex)) in buffer.range(0..expected) {
                    println!("{hex} {path}");
                }
                buffer = buffer.split_off(&expected);
                continue;
            }
        }
        for (_, (path, hex)) in buffer.iter() {
            println!("{hex} {path}");
        }
    });
}

pub(crate) fn calc_and_output_hash_variable(
    algorithm: &str,
    files: Vec<String>,
    use_hmac: bool,
    key: Option<&[u8]>,
    length: usize,
) {
    rayon::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        s.spawn(move |_| {
            files
                .into_iter()
                .enumerate()
                .par_bridge()
                .for_each(|(i, path)| {
                    let content = std::fs::read(&path).unwrap();

                    let sum = match algorithm {
                        "blake2b-variable" => {
                            let mut hasher = if use_hmac {
                                let key = key.expect("use HMAC but not provided a key.");
                                kittycrypto::blake2b::Blake2bVariable::new(Some(key), length)
                                    .expect("create blake2b variable failed")
                            } else {
                                kittycrypto::blake2b::Blake2bVariable::new(None, length)
                                    .expect("create blake2b variable failed")
                            };
                            hasher.write_all(&content).unwrap();
                            hasher.sum_vec()
                        }
                        _ => panic!("unknown hash algorithm: {algorithm}"),
                    };

                    tx.send((i, path, hex::encode(sum))).unwrap();
                });
        });

        let mut buffer = BTreeMap::new();
        let mut expected = 0;
        while let Ok((i, path, hex)) = rx.recv() {
            buffer.insert(i, (path, hex));
            if i <= expected {
                expected += 1;
                for (_, (path, hex)) in buffer.range(0..expected) {
                    println!("{hex} {path}");
                }
                buffer = buffer.split_off(&expected);
                continue;
            }
        }
        for (_, (path, hex)) in buffer.iter() {
            println!("{hex} {path}");
        }
    });
}
