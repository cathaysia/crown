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
                use crate::args::HashAlgorithm;
                use kittycrypto::cuda::mem::CudaMemory;

                let mut all_data = Vec::new();
                let mut file_sizes = Vec::new();
                let mut file_offsets = Vec::new();
                let mut file_paths = Vec::new();

                let mut offset: u32 = 0;
                for path in &files {
                    let content = std::fs::read(path).unwrap();
                    file_sizes.push(content.len() as u32);
                    all_data.extend_from_slice(&content);
                    file_paths.push(path.clone());
                    file_offsets.push(offset);
                    offset += content.len() as u32;
                }

                let all_data = CudaMemory::from_slice_to_device(&all_data).unwrap();
                let file_sizes = CudaMemory::from_slice_to_device(&file_sizes).unwrap();
                let file_offsets = CudaMemory::from_slice_to_device(&file_offsets).unwrap();
                let output_size = match algorithm {
                    HashAlgorithm::Md5Cuda => 16,
                    HashAlgorithm::Sha256Cuda => 32,
                    _ => unreachable!(),
                };
                let mut output =
                    CudaMemory::<u8>::new_pined(output_size * file_paths.len()).unwrap();

                match algorithm {
                    HashAlgorithm::Md5Cuda => {
                        kittycrypto::md5::cuda::md5_sum_batch_cuda(
                            &all_data,
                            &file_sizes,
                            &file_offsets,
                            &mut output,
                        )
                        .unwrap();
                    }
                    HashAlgorithm::Sha256Cuda => {
                        kittycrypto::sha256::cuda::sha256_sum_batch_cuda(
                            &all_data,
                            &file_sizes,
                            &file_offsets,
                            &mut output,
                        )
                        .unwrap();
                    }
                    _ => unreachable!(),
                }

                let output = output.to_vec().unwrap();
                for (i, path) in file_paths.iter().enumerate() {
                    let hash_start = i * output_size;
                    let hash_end = hash_start + output_size;
                    let hash = &output[hash_start..hash_end];
                    println!("{}  {}", hex::encode(hash), path);
                }

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
            let buf = if hex {
                hex::encode(&buf)
            } else if base64 {
                base64::prelude::BASE64_STANDARD.encode(&buf)
            } else {
                format!("{buf:?}")
            };
            if let Some(out) = out {
                std::fs::write(out, buf).unwrap();
            } else {
                println!("{buf}")
            }
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
