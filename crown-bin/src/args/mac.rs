use clap::{Parser, ValueEnum};

/// Message authentication codes (SipHash, KMAC, CMAC-AES).
#[derive(Debug, Parser)]
pub struct ArgsMac {
    pub algorithm: MacAlgorithm,
    /// Key as hex.
    #[clap(long)]
    pub key: String,
    /// Optional custom/salt (KMAC) or IV (GMAC) as hex.
    #[clap(long, default_value = "")]
    pub custom: String,
    /// Input file.
    #[clap(long)]
    pub input: String,
    /// Tag length in bytes (SipHash 8 or 16; KMAC output length).
    #[clap(long, default_value_t = 16)]
    pub length: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum MacAlgorithm {
    SipHash,
    Kmac128,
    Kmac256,
    CmacAes,
}

/// One-time passwords (HOTP / TOTP).
#[derive(Debug, Parser)]
pub struct ArgsOtp {
    /// hotp or totp.
    #[clap(long, default_value = "totp")]
    pub kind: String,
    /// Shared secret as hex.
    #[clap(long)]
    pub key: String,
    /// HOTP counter or TOTP time in seconds.
    #[clap(long, default_value_t = 0)]
    pub counter: u64,
    /// Number of digits (6 or 8).
    #[clap(long, default_value_t = 6)]
    pub digits: usize,
    /// TOTP time step in seconds.
    #[clap(long, default_value_t = 30)]
    pub step: u64,
    /// TOTP start time t0.
    #[clap(long, default_value_t = 0)]
    pub t0: u64,
}
