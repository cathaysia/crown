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
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum KdfAlgorithm {
    Pbkdf2,
    Scrypt,
    Argon2,
    Hkdf,
    Bcrypt,
}
