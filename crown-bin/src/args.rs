mod hash;
pub use hash::*;

mod enc;
pub use enc::*;

mod kdf;
pub use kdf::*;

mod jsasm;
pub use jsasm::*;

use clap::Parser;

#[derive(Debug, Parser)]
pub enum Args {
    Hash(ArgsHash),
    Rand(ArgsRand),
    Enc(ArgsEnc),
    Dec(ArgsDec),
    Kdf(ArgsKdf),
}

#[derive(Debug, Parser)]
pub struct ArgsRand {
    #[clap(long, default_value_t = false)]
    pub hex: bool,
    #[clap(long, default_value_t = false)]
    pub base64: bool,
    #[clap(long)]
    pub out: Option<String>,
    #[clap(default_value = "0")]
    pub size: String,
}
