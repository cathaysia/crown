use kittycrypto::cipher::erased::ErasedAead;

use crate::args::{ArgsDec, EncAlgorithm};

pub fn run_dec(args: ArgsDec) -> anyhow::Result<()> {
    let ArgsDec {
        algorithm,
        key,
        iv,
        aad_file,
        in_file,
        out_file,
        tagin,
    } = args;
    let mut infile = std::fs::read(in_file)?;
    let key = hex::decode(key)?;
    let iv = hex::decode(iv)?;
    let aad = match aad_file {
        Some(aad_file) => std::fs::read(aad_file)?,
        None => vec![],
    };
    let decrypt = match algorithm {
        EncAlgorithm::Chacha20Poly1305 => Some(ErasedAead::new(
            kittycrypto::chacha20poly1305::ChaCha20Poly1305::new(&key)?,
        )),
        EncAlgorithm::XChacha20Poly1305 => Some(ErasedAead::new(
            kittycrypto::chacha20poly1305::XChaCha20Poly1305::new(&key)?,
        )),
    };
    if let Some(cipher) = decrypt {
        match tagin {
            Some(tagfile) => {
                let tag = std::fs::read(tagfile)?;
                cipher.open_in_place_separate_tag(&mut infile, &tag, &iv, &aad)?;
            }
            None => {
                cipher.open_in_place(&mut infile, &iv, &aad)?;
            }
        }
        std::fs::write(out_file, infile)?;
    }

    Ok(())
}
