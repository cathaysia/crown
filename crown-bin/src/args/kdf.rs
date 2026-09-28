use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
pub struct ArgsKdf {
    pub algorithm: KdfAlgorithm,
    #[clap(long)]
    pub password: String,
    #[clap(long)]
    pub salt: String,
    #[clap(long, default_value_t = 4096)]
    pub iterations: u32,
    #[clap(long, default_value_t = 32)]
    pub length: usize,
    #[clap(long = "out")]
    pub out_file: Option<String>,
    #[clap(long, default_value_t = false)]
    pub hex: bool,
    #[clap(long, default_value_t = false)]
    pub base64: bool,
    /// Optional IKM/secret (hex). Defaults to the password bytes when omitted.
    #[clap(long)]
    pub secret: Option<String>,
    /// Optional label/info (utf-8) for TLS1-PRF, SSHKDF, SSKDF, X963KDF.
    #[clap(long, default_value = "")]
    pub label: String,
    /// SSHKDF type letter: A-F (default A).
    #[clap(long, default_value = "A")]
    pub kdf_type: String,
    /// PKCS12KDF id: 1=encryption, 2=MAC, 3=key (default 1).
    #[clap(long, default_value_t = 1)]
    pub id: u8,
    /// SRTP KDF label 0..=7 (default 0).
    #[clap(long, default_value_t = 0)]
    pub srtp_label: u8,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum KdfAlgorithm {
    Pbkdf2,
    Scrypt,
    Argon2,
    Hkdf,
    Bcrypt,
    Pbkdf1,
    Tls1Prf,
    Sskdf,
    SshKdf,
    Pkcs12Kdf,
    SrtpKdf,
    X963Kdf,
}
