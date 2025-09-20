use crate::args::{ArgsHash, HashAlgorithm};
use crate::utils::read_file;
use kittycrypto::{core::CoreWrite, envelope::EvpHash};
use rayon::prelude::*;
use std::collections::BTreeMap;

macro_rules! create_hasher_match {
    (
        $hash:expr, $use_hmac:expr, $key:expr, $length:expr,
        normal: [$(($variant:ident, $method:ident)),* $(,)?],
        blake_fixed: [$(($blake_variant:ident, $blake_method:ident, $size:expr)),* $(,)?],
        blake_variable: [$(($var_variant:ident, $var_method:ident, $default_len:expr)),* $(,)?] $(,)?
    ) => {
        match $hash {
            $(
                HashAlgorithm::$variant => {
                    if $use_hmac {
                        paste::paste! { EvpHash::[<$method _hmac>]($key.unwrap()) }
                    } else {
                        EvpHash::$method()
                    }
                }
            )*
            $(
                HashAlgorithm::$blake_variant => EvpHash::$blake_method($key, $size),
            )*
            $(
                HashAlgorithm::$var_variant => EvpHash::$var_method($key, $length.unwrap_or($default_len)),
            )*
        }
    };
}

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

    calc_and_output_hash(algorithm, files, hmac, key.as_deref(), Some(length));

    Ok(())
}

pub fn create_hasher(
    hash: HashAlgorithm,
    use_hmac: bool,
    key: Option<&[u8]>,
    length: Option<usize>,
) -> Option<EvpHash> {
    if use_hmac && key.is_none() {
        panic!("HMAC key is required for HMAC");
    }

    create_hasher_match!(
        hash, use_hmac, key, length,
        normal: [
            (Md4, new_md4),
            (Md5, new_md5),
            (Sha1, new_sha1),
            (Sha224, new_sha224),
            (Sha256, new_sha256),
            (Sha384, new_sha384),
            (Sha512, new_sha512),
            (Sha512224, new_sha512_224),
            (Sha512256, new_sha512_256),
            (Sha3224, new_sha3_224),
            (Sha3256, new_sha3_256),
            (Sha3384, new_sha3_384),
            (Sha3512, new_sha3_512),
            (Shake128, new_shake128),
            (Shake256, new_shake256),
        ],
        blake_fixed: [
            (Blake2b256, new_blake2b, 32),
            (Blake2b384, new_blake2b, 48),
            (Blake2b512, new_blake2b, 64),
            (Blake2s128, new_blake2s, 16),
            (Blake2s256, new_blake2s, 32),
        ],
        blake_variable: [
            (Blake2b, new_blake2b, 64),
            (Blake2s, new_blake2s, 32),
        ],
    )
    .ok()
}

pub(crate) fn calc_and_output_hash(
    algorithm: HashAlgorithm,
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
                    let mut hasher = create_hasher(algorithm, use_hmac, key, length)
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
