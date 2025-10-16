use clap::{Parser, ValueEnum};
use crown::{
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
            PaddingMode::Pkcs7 => Box::new(crown::padding::Pkcs7),
            PaddingMode::AnsiX923 => Box::new(crown::padding::AnsiX923),
            PaddingMode::Iso10126 => Box::new(crown::padding::Iso10126),
            PaddingMode::Iso7816 => Box::new(crown::padding::Iso7816),
            PaddingMode::NoPadding => Box::new(crown::padding::NoPadding),
            PaddingMode::ZeroPadding => Box::new(crown::padding::ZeroPadding),
        }
    }
}

pub enum Cipher {
    Aead(EvpAeadCipher),
    Stream(EvpStreamCipher),
    Block(EvpBlockCipher),
}

macro_rules! enc_algorithm {
    (
        aead: [$(($aead_enum: ident, $aead_func: ident)),* $(,)*],
        simple_stream: [$($simple: ident),* $(,)*],
        iv_stream: [$($iv_stream: ident),* $(,)*],
        block_cipher: [$($block: ident),* $(,)*],
        rounds_cipher: [$($rounds: ident),* $(,)*]
    ) => {
        paste::paste! {
            #[derive(Debug, Clone, Copy, ValueEnum)]
            #[clap(rename_all = "kebab-case")]
            pub enum EncAlgorithm {
                $(
                    #[doc = $aead_enum " AEAD mode"]
                    $aead_enum,
                )*
                $(
                    #[doc = $simple " stream mode"]
                    $simple,
                )*
                $(
                    #[doc = $iv_stream " stream mode"]
                    $iv_stream,
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
                $(
                    #[doc=$rounds " in Gcm mode"]
                    [<$rounds Gcm>],
                    #[doc=$rounds " in Cbc mode"]
                    [<$rounds Cbc>],
                    #[doc=$rounds " in Ctr mode"]
                    [<$rounds Ctr>],
                    #[doc=$rounds " in Cfb mode"]
                    [<$rounds Cfb>],
                    #[doc=$rounds " in Ofb mode"]
                    [<$rounds Ofb>],
                )*
            }

            impl EncAlgorithm {
                pub fn to_cipher(
                    self,
                    key: &[u8],
                    iv: &[u8],
                    rounds: Option<usize>,
                ) -> CryptoResult<Cipher> {
                    match self {
                        $(
                            EncAlgorithm::$aead_enum => {
                                EvpAeadCipher::[<new_ $aead_func>](&key).map(Cipher::Aead)
                            },
                        )*
                        $(
                            EncAlgorithm::[<$block Gcm>] => {
                                EvpAeadCipher::[<new_ $block:lower _gcm>](&key).map(Cipher::Aead)
                            },
                        )*
                        $(
                            EncAlgorithm::[<$rounds Gcm>] => {
                                EvpAeadCipher::[<new_ $rounds:lower _gcm>](&key, rounds).map(Cipher::Aead)
                            },
                        )*

                        $(
                            EncAlgorithm::$simple => {
                                EvpStreamCipher::[<new_ $simple:lower>](&key).map(Cipher::Stream)
                            },
                        )*
                        $(
                            EncAlgorithm::$iv_stream => {
                                EvpStreamCipher::[<new_ $iv_stream:lower>](&key, &iv).map(Cipher::Stream)
                            },
                        )*
                        $(
                            EncAlgorithm::[<$block Cfb>] => {
                                EvpStreamCipher::[<new_ $block:lower _cfb>](&key, &iv).map(Cipher::Stream)
                            },
                            EncAlgorithm::[<$block Ctr>] => {
                                EvpStreamCipher::[<new_ $block:lower _ctr>](&key, &iv).map(Cipher::Stream)
                            },
                            EncAlgorithm::[<$block Ofb>] => {
                                EvpStreamCipher::[<new_ $block:lower _ofb>](&key, &iv).map(Cipher::Stream)
                            },
                        )*
                        $(
                            EncAlgorithm::[<$rounds Cfb>] => {
                                EvpStreamCipher::[<new_ $rounds:lower _cfb>](&key, &iv, rounds).map(Cipher::Stream)
                            },
                            EncAlgorithm::[<$rounds Ctr>] => {
                                EvpStreamCipher::[<new_ $rounds:lower _ctr>](&key, &iv, rounds).map(Cipher::Stream)
                            },
                            EncAlgorithm::[<$rounds Ofb>] => {
                                EvpStreamCipher::[<new_ $rounds:lower _ofb>](&key, &iv, rounds).map(Cipher::Stream)
                            },
                        )*

                        $(
                            EncAlgorithm::[<$block Cbc>] => {
                                EvpBlockCipher::[<new_ $block:lower _cbc>](&key, &iv).map(Cipher::Block)
                            },
                        )*
                        $(
                            EncAlgorithm::[<$rounds Cbc>] => {
                                EvpBlockCipher::[<new_ $rounds:lower _cbc>](&key, &iv, rounds).map(Cipher::Block)
                            },
                        )*
                    }
                }
            }
        }
    };
}

enc_algorithm!(
    aead: [(Chacha20Poly1305, chacha20_poly1305), (XChacha20Poly1305, xchacha20_poly1305)],
    simple_stream: [Rc4],
    iv_stream: [Salsa20, Chacha20],
    block_cipher: [Aes, Blowfish, Cast5, Des, TripleDes, Tea, Twofish, Xtea, Rc6],
    rounds_cipher: [Rc2, Rc5, Camellia]
);
