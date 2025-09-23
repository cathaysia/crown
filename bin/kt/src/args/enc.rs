use clap::{Parser, ValueEnum};
use kittycrypto::{
    envelope::{EvpAeadCipher, EvpBlockCipher, EvpStreamCipher},
    error::CryptoResult,
    padding::Padding,
};
use strum_macros::EnumString;

#[derive(Debug, Parser)]
pub struct ArgsEnc {
    pub algorithm: EncAlgorithm,
    #[clap(long)]
    pub key: String,
    #[clap(long)]
    pub iv: String,
    #[clap(long = "aad")]
    pub aad_file: Option<String>,
    #[clap(long = "in")]
    pub in_file: String,
    #[clap(long = "out")]
    pub out_file: String,
    #[clap(long)]
    pub tagout: Option<String>,
    #[clap(long)]
    pub rounds: Option<usize>,
    #[clap(long, default_value = "pkcs7")]
    pub padding_mode: PaddingMode,
}

#[derive(Debug, Parser)]
pub struct ArgsDec {
    pub algorithm: EncAlgorithm,
    #[clap(long)]
    pub key: String,
    #[clap(long)]
    pub iv: String,
    #[clap(long = "aad")]
    pub aad_file: Option<String>,
    #[clap(long = "in")]
    pub in_file: String,
    #[clap(long = "out")]
    pub out_file: String,
    #[clap(long)]
    pub tagin: Option<String>,
    #[clap(long)]
    pub rounds: Option<usize>,
    #[clap(long, default_value = "pkcs7")]
    pub padding_mode: PaddingMode,
}

#[derive(Default, Debug, Clone, ValueEnum, EnumString)]
#[clap(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum PaddingMode {
    #[default]
    Pkcs7,
    AnsiX923,
    Iso10126,
    Iso7816,
    NoPadding,
    ZeroPadding,
}

impl From<PaddingMode> for Box<dyn Padding> {
    fn from(value: PaddingMode) -> Self {
        match value {
            PaddingMode::Pkcs7 => Box::new(kittycrypto::padding::Pkcs7),
            PaddingMode::AnsiX923 => Box::new(kittycrypto::padding::AnsiX923),
            PaddingMode::Iso10126 => Box::new(kittycrypto::padding::Iso10126),
            PaddingMode::Iso7816 => Box::new(kittycrypto::padding::Iso7816),
            PaddingMode::NoPadding => Box::new(kittycrypto::padding::NoPadding),
            PaddingMode::ZeroPadding => Box::new(kittycrypto::padding::ZeroPadding),
        }
    }
}

macro_rules! enc_algorithm {
    (
        aead: [$($aead: ident),* $(,)*],
        stream: [$($stream: ident),* $(,)*],
        block: [$($block: ident),* $(,)*]
    ) => {
        paste::paste! {
            #[derive(Debug, Clone, Copy, ValueEnum)]
            #[clap(rename_all = "kebab-case")]
            pub enum EncAlgorithm {
                $(
                    #[doc = $aead " AEAD mode"]
                    $aead,
                )*
                $(
                    #[doc = $stream " stream mode"]
                    $stream,
                )*
                $(
                    #[doc=$block " in Gcm mode"]
                    [<$block Gcm>],
                    #[doc=$block " in Cbc mode"]
                    [<$block Cbc>],
                    #[doc=$block " in Ctr mode"]
                    [<$block Ctr>],
                    #[doc=$block " in Cfb mode"]
                    [<$block Cfb>],
                    #[doc=$block " in Ofb mode"]
                    [<$block Ofb>],
                )*
            }
        }
    };
}

enc_algorithm!(
    aead: [Chacha20Poly1305, XChacha20Poly1305],
    stream: [Chacha20, Rc4, Salsa20],
    block: [Aes, Blowfish, Cast5, Des, TripleDes, Rc2, Rc5, Rc6, Tea, Twofish, Xtea, Idea, Camellia]
);

impl EncAlgorithm {
    pub fn new_aead(
        self,
        key: &[u8],
        rounds: Option<usize>,
    ) -> Option<CryptoResult<EvpAeadCipher>> {
        macro_rules! aead_cipher_create {
            (
                aead: [$(($k:ident, $v:ident)),* $(,)*],
                stream: [$($stream:ident),* $(,)*],
                rounds: [$($rounds:ident),* $(,)*]
            ) => {
                paste::paste! {
                    match self {
                        $(
                            EncAlgorithm::[<$k>] => Some(EvpAeadCipher::[<new_ $v:lower>](&key)),
                        )*
                        $(
                            EncAlgorithm::[<$stream Gcm>] => Some(EvpAeadCipher::[<new_ $stream:lower _gcm>](&key)),
                        )*
                        $(
                            EncAlgorithm::[<$rounds Gcm>] => Some(EvpAeadCipher::[<new_ $rounds:lower _gcm>](&key, rounds)),
                        )*
                        _ => None,
                    }
                }
            };
        }

        aead_cipher_create!(
            aead: [(Chacha20Poly1305, chacha20_poly1305), (XChacha20Poly1305, xchacha20_poly1305)],
            stream: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6],
            rounds: [Rc2, Rc5, Camellia]
        )
    }

    pub fn new_stream(
        self,
        key: &[u8],
        iv: &[u8],
        rounds: Option<usize>,
    ) -> Option<CryptoResult<EvpStreamCipher>> {
        macro_rules! stream_cipher {
            (
                simple: [$($simple:ident),* $(,)*],
                stream: [$($stream:ident),* $(,)*],
                block: [$($block:ident),* $(,)*],
                rounds: [$($rounds:ident),* $(,)*]
            ) => {
                paste::paste! {
                    match self {
                        $(
                            EncAlgorithm::$simple => Some(EvpStreamCipher::[<new_ $simple:lower>](&key)),
                        )*
                        $(
                            EncAlgorithm::$stream => Some(EvpStreamCipher::[<new_ $stream:lower>](&key, &iv)),
                        )*
                        $(
                            EncAlgorithm::[<$block Cfb>] => Some(EvpStreamCipher::[<new_ $block:lower _cfb>](&key, &iv)),
                            EncAlgorithm::[<$block Ctr>] => Some(EvpStreamCipher::[<new_ $block:lower _ctr>](&key, &iv)),
                            EncAlgorithm::[<$block Ofb>] => Some(EvpStreamCipher::[<new_ $block:lower _ofb>](&key, &iv)),
                        )*
                        $(
                            EncAlgorithm::[<$rounds Cfb>] => Some(EvpStreamCipher::[<new_ $rounds:lower _cfb>](&key, &iv, rounds)),
                            EncAlgorithm::[<$rounds Ctr>] => Some(EvpStreamCipher::[<new_ $rounds:lower _ctr>](&key, &iv, rounds)),
                            EncAlgorithm::[<$rounds Ofb>] => Some(EvpStreamCipher::[<new_ $rounds:lower _ofb>](&key, &iv, rounds)),
                        )*
                        _ => None
                    }

                }
            };
        }

        stream_cipher!(
            simple: [Rc4],
            stream: [Salsa20, Chacha20],
            block: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6],
            rounds: [Rc2, Rc5, Camellia]
        )
    }

    pub fn new_block(
        self,
        key: &[u8],
        iv: &[u8],
        rounds: Option<usize>,
    ) -> Option<CryptoResult<EvpBlockCipher>> {
        macro_rules! padding_cipher {
            (
                block: [$($block:ident),* $(,)*],
                rounds: [$($rounds:ident),* $(,)*]
            ) => {
                paste::paste! {
                    match self {
                        $(
                            EncAlgorithm::[<$block Cbc>] => {
                                Some(EvpBlockCipher::[<new_ $block:lower _cbc>](&key, &iv))
                            },
                        )*
                        $(
                            EncAlgorithm::[<$rounds Cbc>] => Some(EvpBlockCipher::[<new_ $rounds:lower _cbc>](&key, &iv, rounds)),
                        )*
                        _=> None
                    }

                }
            };
        }

        padding_cipher!(
            block: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Idea, Rc6],
            rounds: [Rc2, Rc5, Camellia]
        )
    }
}
