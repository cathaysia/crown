use std::fmt::Display;

use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
pub enum Args {
    Hash(ArgsHash),
    Rand(ArgsRand),
}

#[derive(Debug, Parser)]
pub struct ArgsRand {
    #[clap(long, default_value_t = false)]
    pub hex: bool,
    #[clap(long, default_value_t = false)]
    pub base64: bool,
    #[clap(long)]
    pub out: Option<String>,
    #[clap(default_value_t = 0)]
    pub num: usize,
}

#[derive(Debug, Parser)]
pub struct ArgsHash {
    #[clap(default_value = "sha256", required = true)]
    pub algorithm: HashAlgorithm,
    #[clap(short, long, default_value_t = true)]
    pub text: bool,
    #[clap(short, long, default_value_t = false)]
    pub binary: bool,
    #[clap(short, long, default_value_t = false)]
    pub check: bool,
    #[clap(required = true)]
    pub files: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct Md5 {
    #[clap(short, long, default_value_t = true)]
    pub text: bool,
    #[clap(short, long, default_value_t = false)]
    pub binary: bool,
    #[clap(short, long, default_value_t = false)]
    pub check: bool,
    pub files: Vec<String>,
}

#[derive(Debug, Default, Clone, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum HashAlgorithm {
    Md4,
    #[default]
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    #[clap(name = "sha512-224")]
    Sha512224,
    #[clap(name = "sha512-256")]
    Sha512256,
    #[clap(name = "sha3-224")]
    Sha3224,
    #[clap(name = "sha3-256")]
    Sha3256,
    #[clap(name = "sha3-384")]
    Sha3384,
    #[clap(name = "sha3-512")]
    Sha3512,
    #[cfg(feature = "cuda")]
    Md5Cuda,
    #[cfg(feature = "cuda")]
    Sha256Cuda,
}

impl HashAlgorithm {
    #[cfg(feature = "cuda")]
    pub fn is_cuda(&self) -> bool {
        match self {
            #[cfg(feature = "cuda")]
            Self::Md5Cuda | Self::Sha256Cuda => true,
            _ => false,
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = match self {
            Self::Md4 => "md4",
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha224 => "sha224",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha512224 => "sha512-224",
            Self::Sha512256 => "sha512-256",
            Self::Sha3224 => "sha3-224",
            Self::Sha3256 => "sha3-256",
            Self::Sha3384 => "sha3-384",
            Self::Sha3512 => "sha3-512",
            #[cfg(feature = "cuda")]
            Self::Md5Cuda => "md5-cuda",
            #[cfg(feature = "cuda")]
            Self::Sha256Cuda => "sha256-cuda",
        };

        write!(f, "{}", v)
    }
}
