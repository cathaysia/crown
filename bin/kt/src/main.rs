#[cfg(feature = "cuda")]
mod cuda;
mod utils;

use crate::args::ArgsHash;
use args::ArgsRand;
use base64::Engine;
use clap::Parser;
use kittycrypto::hash::ErasedHash;
use rayon::prelude::*;
use std::{collections::BTreeMap, io::Write};
use tracing::*;
use utils::init_logger;

mod args;

fn main() -> anyhow::Result<()> {
    init_logger();

    let prog = std::env::args().next();
    let prog = {
        prog.and_then(|prog| {
            let path = std::path::Path::new(&prog);
            path.file_stem().map(|v| v.to_string_lossy().to_string())
        })
        .unwrap_or("md5sum".into())
        .to_lowercase()
    };
    if prog != env!("CARGO_PKG_NAME").to_lowercase() {
        return main_mock(&prog);
    }

    let args = args::Args::parse();
    trace!(?args);
    match args {
        args::Args::Hash(args_hash) => {
            let ArgsHash {
                algorithm, files, ..
            } = args_hash;

            #[cfg(feature = "cuda")]
            if algorithm.is_cuda() {
                cuda::calc_and_output_hash(algorithm, files);
                return Ok(());
            }

            calc_and_output_hash(&algorithm.to_string(), files);
        }
        args::Args::Rand(ArgsRand {
            hex,
            base64,
            out,
            num,
        }) => {
            let mut buf = vec![0u8; num];
            rand::fill(buf.as_mut_slice());
            let mut out: Box<dyn Write> = if let Some(out) = out {
                Box::new(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(out)
                        .unwrap(),
                )
            } else {
                Box::new(std::io::stdout())
            };

            if hex {
                write!(out, "{}", hex::encode(&buf)).unwrap();
            } else if base64 {
                write!(out, "{}", base64::prelude::BASE64_STANDARD.encode(&buf)).unwrap();
            } else {
                out.write_all(&buf).unwrap();
            };
        }
    }

    Ok(())
}

fn main_mock(prog: &str) -> anyhow::Result<()> {
    debug!("mock as {prog}");
    let arg = args::Md5::parse();
    calc_and_output_hash(prog, arg.files);

    Ok(())
}

pub fn create_hash_from_str(hash: &str) -> Option<ErasedHash> {
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
        _ => return None,
    })
}

fn calc_and_output_hash(algorithm: &str, files: Vec<String>) {
    rayon::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        s.spawn(move |_| {
            files
                .into_iter()
                .enumerate()
                .par_bridge()
                .for_each(|(i, path)| {
                    let content = std::fs::read(&path).unwrap();
                    let mut hasher = create_hash_from_str(algorithm)
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
