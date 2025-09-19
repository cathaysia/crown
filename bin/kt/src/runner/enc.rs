use kittycrypto::{
    aes::Aes,
    blowfish::Blowfish,
    cast5::Cast5,
    cipher::{cbc::CbcEncAble, padding::*},
    des::{Des, TripleDes},
    envelope::AeadAlgorithm,
    envelope::EvpAeadCipher,
    envelope::EvpStreamCipher,
    rc2::Rc2,
    rc5::Rc5,
    rc6::Rc6,
    tea::Tea,
    twofish::Twofish,
    xtea::Xtea,
};

use crate::args::{ArgsEnc, EncAlgorithm, PaddingMode};

pub fn run_enc(args: ArgsEnc) -> anyhow::Result<()> {
    let ArgsEnc {
        algorithm,
        key,
        iv,
        aad_file,
        in_file,
        out_file,
        tagout,
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
        .map(|v| EvpAeadCipher::new(v, &key, Some(rounds)).unwrap());
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
                        EncAlgorithm::[<$name Cfb>] => EvpStreamCipher::[<new_ $name:lower _cfb>](&key, &iv, rounds).ok(),
                        EncAlgorithm::[<$name Ctr>] => EvpStreamCipher::[<new_ $name:lower _ctr>](&key, &iv, rounds).ok(),
                        EncAlgorithm::[<$name Ofb>] => EvpStreamCipher::[<new_ $name:lower _ofb>](&key, &iv, rounds).ok(),
                    )*
                    _ => None,
                }

            }
        };
    }

    let mut stream_cipher =
        stream_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,);
    if stream_cipher.is_none() {
        stream_cipher = stream_cipher!(#rc Rc2, Rc5, Rc6,);
    }
    if let Some(mut cipher) = stream_cipher {
        cipher.encrypt(&mut infile)?;
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
                            impl_padding_mode!($name::new(&key)?.to_cbc_enc(&iv))
                        },
                    )*
                    EncAlgorithm::Rc2Cbc => impl_padding_mode!(Rc2::new(&key, rounds)?.to_cbc_enc(&iv)),
                    EncAlgorithm::Rc5Cbc => impl_padding_mode!(Rc5::new(&key, rounds)?.to_cbc_enc(&iv)),
                    EncAlgorithm::Rc6Cbc => impl_padding_mode!(Rc6::new(&key, rounds)?.to_cbc_enc(&iv)),
                    _=> return Ok(())
                }

            }
        };

    }

    let mut padding_cipher =
        padding_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,);
    padding_cipher.encrypt_alloc(&mut infile).unwrap();
    std::fs::write(out_file, infile)?;

    Ok(())
}
