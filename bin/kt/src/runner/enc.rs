use kittycrypto::cipher::erased::ErasedAead;

use crate::args::{ArgsEnc, EncAlgorithm};

pub fn run_enc(args: ArgsEnc) -> anyhow::Result<()> {
    let ArgsEnc {
        algorithm,
        key,
        iv,
        aad_file,
        in_file,
        out_file,
        tagout,
    } = args;
    let mut infile = std::fs::read(in_file)?;
    let key = hex::decode(key)?;
    let iv = hex::decode(iv)?;
    let aad = match aad_file {
        Some(aad_file) => std::fs::read(aad_file)?,
        None => vec![],
    };

    let aead_cipher = match algorithm {
        EncAlgorithm::Chacha20Poly1305 => Some(ErasedAead::new(
            kittycrypto::chacha20poly1305::ChaCha20Poly1305::new(&key)?,
        )),
        EncAlgorithm::XChacha20Poly1305 => Some(ErasedAead::new(
            kittycrypto::chacha20poly1305::XChaCha20Poly1305::new(&key)?,
        )),
    };
    if let Some(cipher) = aead_cipher {
        match tagout {
            Some(tagout) => {
                let tag = cipher.seal_in_place_separate_tag(&mut infile, &iv, &aad)?;
                std::fs::write(tagout, tag)?;
            }
            None => {
                cipher.seal_in_place_append_tag(&mut infile, &iv, &aad)?;
            }
        }
        std::fs::write(out_file, infile)?;
    }

    Ok(())
}
