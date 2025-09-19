use crate::args::ArgsHash;
use crate::utils::read_file;
use kittycrypto::{
    core::CoreWrite,
    envelope::{EvpHash, HashAlgorithm},
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

    calc_and_output_hash(
        &algorithm.to_string(),
        files,
        hmac,
        key.as_deref(),
        Some(length),
    );

    Ok(())
}

pub fn create_hash_from_str(
    hash: &str,
    use_hmac: bool,
    key: Option<&[u8]>,
    length: Option<usize>,
) -> Option<EvpHash> {
    if use_hmac && key.is_none() {
        panic!("HMAC key is required for HMAC");
    }

    let alg =
        HashAlgorithm::from_str(hash).unwrap_or_else(|_| panic!("Unknown hash algorithm: {hash}"));
    EvpHash::new(alg, key, length).ok()
}

pub(crate) fn calc_and_output_hash(
    algorithm: &str,
    files: Vec<String>,
    use_hmac: bool,
    key: Option<&[u8]>,
    length: Option<usize>,
) {
    rayon::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        s.spawn(move |_| {
            files
                .into_iter()
                .enumerate()
                .par_bridge()
                .for_each(|(i, path)| {
                    let c = read_file(&path).unwrap();
                    let content = c.as_ref();
                    let mut hasher = create_hash_from_str(algorithm, use_hmac, key, length)
                        .unwrap_or_else(|| panic!("unknown hash algorithm: {algorithm}"));

                    hasher.write_all(content).unwrap();
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
