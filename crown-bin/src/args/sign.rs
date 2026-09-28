use clap::{Parser, ValueEnum};

/// Digital signatures (Ed25519).
#[derive(Debug, Parser)]
pub struct ArgsSign {
    /// Algorithm.
    #[clap(long, default_value = "ed25519")]
    pub algorithm: SignAlgorithm,
    /// Operation: keygen, sign, or verify.
    pub op: String,
    /// Secret key as hex (sign) or public key as hex (verify).
    #[clap(long, default_value = "")]
    pub key: String,
    /// Message file (sign/verify).
    #[clap(long)]
    pub input: Option<String>,
    /// Signature file (verify) or output (sign).
    #[clap(long)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum SignAlgorithm {
    Ed25519,
    Ed448,
}
