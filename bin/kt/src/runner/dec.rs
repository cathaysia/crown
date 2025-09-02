use kittycrypto::{
    aes::Aes,
    chacha20::Chacha20,
    cipher::{
        erased::{ErasedAead, ErasedStreamCipher},
        gcm::GcmAble,
    },
    rc4::Rc4,
    sala20::Sala20,
};

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
        EncAlgorithm::AesGcm => Some(ErasedAead::new(Aes::new(&key)?.to_gcm()?)),
        _ => None,
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
        std::fs::write(&out_file, &infile)?;
    }

    let stream_cipher = match algorithm {
        EncAlgorithm::Rc4 => Some(ErasedStreamCipher::new(Rc4::new(&key)?)),
        // EncAlgorithm::Rc6Ctr => Some(ErasedStreamCipher::new(Rc6::new(&key, 20).to_ctr(&iv)?)),
        EncAlgorithm::Salsa20 => Some(ErasedStreamCipher::new(Sala20::new(&key, &iv)?)),
        EncAlgorithm::Chacha20 => Some(ErasedStreamCipher::new(
            Chacha20::new_unauthenticated_cipher(&key, &iv)?,
        )),
        // EncAlgorithm::AesCtr => Some(ErasedStreamCipher::new(Aes::new(&key)?.to_ctr(&iv)?)),
        _ => None,
    };

    if let Some(mut cipher) = stream_cipher {
        cipher.xor_key_stream(&mut infile)?;
        std::fs::write(out_file, infile)?;
    }
    Ok(())
}
