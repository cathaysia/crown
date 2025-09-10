use crate::args::ArgsHash;
use kittycrypto::{
    core::{CoreRead, CoreWrite},
    envelope::{HashAlgorithm, MessageDigest},
    hash::HashVariable,
};
use rayon::prelude::*;
use std::{collections::BTreeMap, str::FromStr};

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
        crate::cuda::calc_and_output_hash(algorithm, files);
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
        crate::args::HashAlgorithm::Shake128 | crate::args::HashAlgorithm::Shake256 => {
            calc_and_output_hash_shake(&algorithm.to_string(), files, length);
        }
        _ => {
            calc_and_output_hash(&algorithm.to_string(), files, hmac, key.as_deref());
        }
    }

    Ok(())
}

pub fn create_hash_from_str(
    hash: &str,
    use_hmac: bool,
    key: Option<&[u8]>,
) -> Option<MessageDigest> {
    if !use_hmac && key.is_none() {
        panic!("HMAC key is required for HMAC");
    }

    let alg =
        HashAlgorithm::from_str(hash).unwrap_or_else(|_| panic!("Unknown hash algorithm: {hash}"));
    MessageDigest::new(alg, key).ok()
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

pub(crate) fn calc_and_output_hash_shake(algorithm: &str, files: Vec<String>, length: usize) {
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
                        "shake128" => {
                            let mut shake = kittycrypto::sha3::new_shake128();
                            shake.write_all(&content).unwrap();
                            let mut result = vec![0u8; length];
                            std::io::Read::read_exact(
                                &mut shake as &mut dyn CoreRead as _,
                                &mut result,
                            )
                            .unwrap();
                            result
                        }
                        "shake256" => {
                            let mut shake = kittycrypto::sha3::new_shake256();
                            shake.write_all(&content).unwrap();
                            let mut result = vec![0u8; length];
                            std::io::Read::read_exact(&mut shake as &mut dyn CoreRead, &mut result)
                                .unwrap();
                            result
                        }
                        _ => panic!("unknown shake algorithm: {algorithm}"),
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
