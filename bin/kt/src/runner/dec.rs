use kittycrypto::{
    envelope::{EvpAeadCipher, EvpBlockCipher, EvpStreamCipher},
    padding::*,
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
    macro_rules! aead_cipher_create {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    EncAlgorithm::Chacha20Poly1305 => EvpAeadCipher::new_chacha20_poly1305(&key).ok(),
                    EncAlgorithm::XChacha20Poly1305 => EvpAeadCipher::new_xchacha20_poly1305(&key).ok(),
                    $(
                        EncAlgorithm::[<$name Gcm>] => EvpAeadCipher::[<new_ $name:lower _gcm>](&key).ok(),
                    )*
                    _ => None,
                }
            }
        };
        (#rc $($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    $(
                        EncAlgorithm::[<$name Gcm>] => EvpAeadCipher::[<new_ $name:lower _gcm>](&key, Some(rounds)).ok(),
                    )*
                    _ => None,
                }
            }
        };
    }

    let mut aead_cipher =
        aead_cipher_create!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6,);
    if aead_cipher.is_none() {
        aead_cipher = aead_cipher_create!(#rc Rc2, Rc5, Camellia,);
    }
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
                    EncAlgorithm::Rc4 => EvpStreamCipher::new_rc4(&key).ok(),
                    EncAlgorithm::Salsa20 =>EvpStreamCipher::new_salsa20(&key, &iv).ok(),
                    EncAlgorithm::Chacha20 => EvpStreamCipher::new_chacha20(&key, &iv).ok(),
                    $(
                        EncAlgorithm::[<$name Cfb>] => EvpStreamCipher::[<new_ $name:lower _cfb>](&key, &iv).ok(),
                        EncAlgorithm::[<$name Ctr>] => EvpStreamCipher::[<new_ $name:lower _ctr>](&key, &iv).ok(),
                        EncAlgorithm::[<$name Ofb>] => EvpStreamCipher::[<new_ $name:lower _ofb>](&key, &iv).ok(),
                    )*
                    _ => None
                }

            }
        };
        (#rc $($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    $(
                        EncAlgorithm::[<$name Cfb>] => EvpStreamCipher::[<new_ $name:lower _cfb>](&key, &iv, Some(rounds)).ok(),
                        EncAlgorithm::[<$name Ctr>] => EvpStreamCipher::[<new_ $name:lower _ctr>](&key, &iv, Some(rounds)).ok(),
                        EncAlgorithm::[<$name Ofb>] => EvpStreamCipher::[<new_ $name:lower _ofb>](&key, &iv, Some(rounds)).ok(),
                    )*
                    _ => None,
                }

            }
        };
    }

    let mut stream_cipher =
        stream_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6,);
    if stream_cipher.is_none() {
        stream_cipher = stream_cipher!(#rc Rc2, Rc5, Camellia,);
    }
    if let Some(mut cipher) = stream_cipher {
        cipher.decrypt(&mut infile)?;
        std::fs::write(out_file, infile)?;
        return Ok(());
    }

    macro_rules! padding_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    $(
                        EncAlgorithm::[<$name Cbc>] => {
                            EvpBlockCipher::[<new_ $name:lower _cbc>](
                               &key, &iv
                            )
                        },
                    )*
                    EncAlgorithm::Rc2Cbc => EvpBlockCipher::new_rc2_cbc(&key, &iv, Some(rounds)),
                    EncAlgorithm::Rc5Cbc => EvpBlockCipher::new_rc5_cbc(&key, &iv, Some(rounds)),
                    EncAlgorithm::CamelliaCbc => EvpBlockCipher::new_camellia_cbc(&key, &iv, Some(rounds)),
                    _=> return Ok(())
                }

            }
        };

    }
    if let Ok(mut padding_cipher) =
        padding_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6,)
    {
        let mode: Box<dyn Padding> = match padding_mode {
            PaddingMode::Pkcs7 => Box::new(kittycrypto::padding::Pkcs7),
            PaddingMode::AnsiX923 => Box::new(kittycrypto::padding::AnsiX923),
            PaddingMode::Iso10126 => Box::new(kittycrypto::padding::Iso10126),
            PaddingMode::Iso7816 => Box::new(kittycrypto::padding::Iso7816),
            PaddingMode::NoPadding => Box::new(kittycrypto::padding::NoPadding),
            PaddingMode::ZeroPadding => Box::new(kittycrypto::padding::ZeroPadding),
        };
        padding_cipher.set_padding(mode);

        padding_cipher.encrypt_alloc(&mut infile).unwrap();
        std::fs::write(out_file, infile)?;
        return Ok(());
    }

    Ok(())
}
