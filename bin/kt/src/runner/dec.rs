use kittycrypto::{
    aes::Aes,
    blowfish::Blowfish,
    cast5::Cast5,
    chacha20::Chacha20,
    cipher::{
        cbc::CbcDecAble,
        cfb::CfbAble,
        ctr::CtrAble,
        erased::{ErasedAead, ErasedStreamCipher},
        gcm::GcmAble,
        ofb::OfbAble,
        padding::*,
    },
    des::{Des, TripleDes},
    rc2::Rc2,
    rc4::Rc4,
    rc5::Rc5,
    rc6::Rc6,
    sala20::Sala20,
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

    macro_rules! stream_cipher {
        ($($name:ident,)*) => {
            paste::paste! {
                match algorithm {
                    EncAlgorithm::Rc4 => Some(ErasedStreamCipher::new(Rc4::new(&key)?)),
                    EncAlgorithm::Salsa20 => Some(ErasedStreamCipher::new(Sala20::new(&key, &iv)?)),
                    EncAlgorithm::Chacha20 => Some(ErasedStreamCipher::new(
                        Chacha20::new_unauthenticated_cipher(&key, &iv)?,
                    )),
                    $(
                        EncAlgorithm::[<$name Cfb>] => Some(ErasedStreamCipher::new($name::new(&key)?.to_cfb_decrypter(&iv)?)),
                        EncAlgorithm::[<$name Ctr>] => Some(ErasedStreamCipher::new($name::new(&key)?.to_ctr(&iv)?)),
                        EncAlgorithm::[<$name Ofb>] => Some(ErasedStreamCipher::new($name::new(&key)?.to_ofb(&iv)?)),
                    )*
                    EncAlgorithm::Rc2Cfb => Some(ErasedStreamCipher::new(Rc2::new(&key, rounds)?.to_cfb_decrypter(&iv)?)),
                    EncAlgorithm::Rc2Ctr => Some(ErasedStreamCipher::new(Rc2::new(&key, rounds)?.to_ctr(&iv)?)),
                    EncAlgorithm::Rc2Ofb => Some(ErasedStreamCipher::new(Rc2::new(&key, rounds)?.to_ofb(&iv)?)),
                    EncAlgorithm::Rc5Cfb => Some(ErasedStreamCipher::new(Rc5::new(&key, rounds)?.to_cfb_decrypter(&iv)?)),
                    EncAlgorithm::Rc5Ctr => Some(ErasedStreamCipher::new(Rc5::new(&key, rounds)?.to_ctr(&iv)?)),
                    EncAlgorithm::Rc5Ofb => Some(ErasedStreamCipher::new(Rc5::new(&key, rounds)?.to_ofb(&iv)?)),
                    EncAlgorithm::Rc6Cfb => Some(ErasedStreamCipher::new(Rc6::new(&key, rounds)?.to_cfb_decrypter(&iv)?)),
                    EncAlgorithm::Rc6Ctr => Some(ErasedStreamCipher::new(Rc6::new(&key, rounds)?.to_ctr(&iv)?)),
                    EncAlgorithm::Rc6Ofb => Some(ErasedStreamCipher::new(Rc6::new(&key, rounds)?.to_ofb(&iv)?)),                 _ => None,
                }

            }
        };

    }

    let stream_cipher = stream_cipher!(Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea,);

    if let Some(mut cipher) = stream_cipher {
        cipher.xor_key_stream(&mut infile)?;
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
            ErasedBlockPadding::new($b.to_padding_crypt::<$p>())
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
