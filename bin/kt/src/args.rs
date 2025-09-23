mod hash;
pub use hash::*;

mod enc;
pub use enc::*;

mod kdf;
pub use kdf::*;

mod dd;
pub use dd::*;

use clap::Parser;

#[derive(Debug, Parser)]
pub enum Args {
    Hash(ArgsHash),
    Rand(ArgsRand),
    Enc(ArgsEnc),
    Dec(ArgsDec),
    Kdf(ArgsKdf),
    Dd(ArgsDd),
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
