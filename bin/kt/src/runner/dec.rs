use kittycrypto::{
    aes::Aes,
    blowfish::Blowfish,
    cast5::Cast5,
    cipher::{cbc::CbcDecAble, padding::*},
    des::{Des, TripleDes},
    envelope::AeadAlgorithm,
    envelope::AeadCipher,
    envelope::EvpStreamCipher,
    envelope::StreamCipherAlgorithm,
    rc2::Rc2,
    rc5::Rc5,
    rc6::Rc6,
    tea::Tea,
    twofish::Twofish,
    xtea::Xtea,
};

use crate::args::{ArgsDec, EncAlgorithm, PaddingMode};

pub fn run_dec(args: ArgsDec) -> anyhow::Result<()> {
    let ArgsDec {
        algorithm,
        key,
        iv,
        aad_file,
        in_file,
        out_file,
        tagin,
        rounds,
        padding_mode,
    } = args;
    let mut infile = std::fs::read(in_file)?;
    let key = hex::decode(key)?;
    let iv = hex::decode(iv)?;
    let aad = match aad_file {
        Some(aad_file) => std::fs::read(aad_file)?,
        None => vec![],
    };
    macro_rules! aead_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    EncAlgorithm::Chacha20Poly1305 => Some(AeadAlgorithm::Chacha20Poly1305),
                    EncAlgorithm::XChacha20Poly1305 => Some(AeadAlgorithm::XChacha20Poly1305),
                    $(
                        EncAlgorithm::[<$name Gcm>] => Some(AeadAlgorithm::[<$name Gcm>]),
                    )*
                    EncAlgorithm::Rc2Gcm => Some(AeadAlgorithm::Rc2Gcm),
                    EncAlgorithm::Rc5Gcm => Some(AeadAlgorithm::Rc5Gcm),
                    EncAlgorithm::Rc6Gcm => Some(AeadAlgorithm::Rc6Gcm),
                    _ => None,
                }

            }
        };

    }

    let aead_cipher = aead_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,)
        .map(|v| AeadCipher::new(v, &key, Some(rounds)).unwrap());

    if let Some(cipher) = aead_cipher {
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
        return Ok(());
    }

    macro_rules! stream_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    EncAlgorithm::Rc4 => Some(StreamCipherAlgorithm::Rc4),
                    EncAlgorithm::Salsa20 => Some(StreamCipherAlgorithm::Salsa20),
                    EncAlgorithm::Chacha20 => Some(StreamCipherAlgorithm::Chacha20),
                    $(
                        EncAlgorithm::[<$name Cfb>] => Some(StreamCipherAlgorithm::[<$name Cfb>]),
                        EncAlgorithm::[<$name Ctr>] => Some(StreamCipherAlgorithm::[<$name Ctr>]),
                        EncAlgorithm::[<$name Ofb>] => Some(StreamCipherAlgorithm::[<$name Ofb>]),
                    )*
                    _ => None
                }

            }
        };

    }

    let stream_cipher =
        stream_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc2, Rc5, Rc6,)
            .map(|v| EvpStreamCipher::new(v, &key, &iv, Some(rounds)).unwrap());

    if let Some(mut cipher) = stream_cipher {
        cipher.decrypt(&mut infile)?;
        std::fs::write(out_file, infile)?;
        return Ok(());
    }

    macro_rules! impl_padding_mode {
        ($b:expr) => {
            match padding_mode {
                PaddingMode::Pkcs7 => impl_padding_mode!($b, Pkcs7),
                PaddingMode::AnsiX923 => impl_padding_mode!($b, AnsiX923),
                PaddingMode::Iso10126 => impl_padding_mode!($b, Iso10126),
                PaddingMode::Iso7816 => impl_padding_mode!($b, Iso7816),
                PaddingMode::NoPadding => impl_padding_mode!($b, NoPadding),
                PaddingMode::ZeroPadding => impl_padding_mode!($b, ZeroPadding),
            }
        };
        ($b:expr, $p:ident) => {
            ErasedBlockPadding::new($b.to_padding_crypt($p))
        };
    }

    macro_rules! padding_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    $(
                        EncAlgorithm::[<$name Cbc>] => {
                            Some(impl_padding_mode!($name::new(&key)?.to_cbc_dec(&iv)))
                        },
                    )*
                    EncAlgorithm::Rc2Cbc => Some(impl_padding_mode!(Rc2::new(&key, rounds)?.to_cbc_dec(&iv))),
                    EncAlgorithm::Rc5Cbc => Some(impl_padding_mode!(Rc5::new(&key, rounds)?.to_cbc_dec(&iv))),
                    EncAlgorithm::Rc6Cbc => Some(impl_padding_mode!(Rc6::new(&key, rounds)?.to_cbc_dec(&iv))),
                    _=> None
                }

            }
        };

    }

    if let Some(mut padding_cipher) =
        padding_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,)
    {
        padding_cipher.encrypt_alloc(&mut infile).unwrap();
        std::fs::write(out_file, infile)?;
        return Ok(());
    }

    Ok(())
}
