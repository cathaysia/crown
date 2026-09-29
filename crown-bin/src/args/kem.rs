use clap::{Parser, ValueEnum};

/// ML-KEM key encapsulation (FIPS 203).
#[derive(Debug, Parser)]
pub struct ArgsKem {
    /// Operation: keygen, encaps, or decaps.
    pub op: String,
    /// Parameter set.
    #[clap(long, default_value = "ml-kem-768")]
    pub algorithm: KemAlgorithm,
    /// Seed as hex (64 bytes) for keygen; secret key as hex for decaps.
    #[clap(long, default_value = "")]
    pub key: String,
    /// Public key as hex (encaps) or ciphertext file (decaps).
    #[clap(long, default_value = "")]
    pub public: String,
    /// Ciphertext file for encaps output / decaps input.
    #[clap(long)]
    pub input: Option<String>,
    /// Output file for ciphertext (encaps) or shared secret.
    #[clap(long)]
    pub output: Option<String>,
    /// Ephemeral message m as hex (32 bytes) for deterministic encaps.
    #[clap(long, default_value = "")]
    pub message: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}
