use kittycrypto::cipher::Aead;

use crate::args::ArgsDec;

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
    match algorithm {
        crate::args::EncAlgorithm::Chacha20Poly1305 => {
            let mut infile = std::fs::read(in_file)?;
            let key = hex::decode(key)?;
            let iv = hex::decode(iv)?;
            let aad = match aad_file {
                Some(aad_file) => std::fs::read(aad_file)?,
                None => vec![],
            };

            let cipher = kittycrypto::chacha20poly1305::ChaCha20Poly1305::new(&key)?;

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
    }

    Ok(())
}
