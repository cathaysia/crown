mod utils;

use clap::Parser;
use kittycrypto::hash::ErasedHash;
use std::io::Write;
use tracing::*;
use utils::init_logger;

use crate::args::ArgsHash;

mod args;

fn main() -> anyhow::Result<()> {
    init_logger();

    let prog = std::env::args().next();
    let prog = {
        prog.map(|prog| {
            let path = std::path::Path::new(&prog);
            path.file_stem().map(|v| v.to_string_lossy().to_string())
        })
        .flatten()
        .unwrap_or("md5sum".into())
        .to_lowercase()
    };
    if prog != env!("CARGO_PKG_NAME").to_lowercase() {
        return main_mock(&prog);
    }

    let args = args::Args::parse();
    match args {
        args::Args::Hash(args_hash) => {
            let ArgsHash {
                algorithm, files, ..
            } = args_hash;

            for path in files {
                let content = std::fs::read(&path).unwrap();
                let mut hasher = create_hash_from_str(&algorithm.to_string())
                    .unwrap_or_else(|| panic!("unknown hash algorithm: {algorithm}"));

                hasher.write_all(&content).unwrap();
                let sum = hasher.sum();
                println!("{}  {}", hex::encode(sum), path);
            }
        }
    }

    Ok(())
}

fn main_mock(prog: &str) -> anyhow::Result<()> {
    debug!("mock as {prog}");
    let arg = args::Md5::parse();
    for path in arg.files {
        let content = std::fs::read(&path).unwrap();
        let mut hasher = create_hash_from_str(prog).unwrap_or_else(|| {
            error!("mock as {prog} failed, fallback to md5!");
            ErasedHash::new(kittycrypto::md5::Md5::default())
        });

        hasher.write_all(&content).unwrap();
        let sum = hasher.sum();
        println!("{}  {}", hex::encode(sum), path);
    }
    Ok(())
}

pub fn create_hash_from_str(hash: &str) -> Option<ErasedHash> {
    Some(match hash {
        "md4" | "md4sum" => ErasedHash::new(kittycrypto::md4::Md4::default()),
        "md5" | "md5sum" => ErasedHash::new(kittycrypto::md5::Md5::default()),
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
