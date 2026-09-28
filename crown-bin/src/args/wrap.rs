use clap::Parser;

/// AES Key Wrap / Unwrap (RFC 3394 / RFC 5649).
#[derive(Debug, Parser)]
pub struct ArgsWrap {
    /// Wrap (default) or unwrap.
    #[clap(long, default_value_t = false)]
    pub unwrap: bool,
    /// Use RFC 5649 padded mode.
    #[clap(long, default_value_t = false)]
    pub padded: bool,
    /// KEK as hex (16/24/32 bytes).
    #[clap(long)]
    pub key: String,
    /// Input file (key material).
    #[clap(long)]
    pub input: String,
    /// Output file.
    #[clap(long)]
    pub output: String,
}

/// FF1 format-preserving encryption (NIST SP 800-38G, decimal strings).
#[derive(Debug, Parser)]
pub struct ArgsFf1 {
    /// Decrypt instead of encrypt.
    #[clap(long, default_value_t = false)]
    pub decrypt: bool,
    /// AES key as hex (16/24/32 bytes).
    #[clap(long)]
    pub key: String,
    /// Tweak as hex (may be empty).
    #[clap(long, default_value = "")]
    pub tweak: String,
    /// Decimal digit string.
    pub input: String,
}
