mod hash;
pub use hash::*;

mod enc;
pub use enc::*;

mod kdf;
pub use kdf::*;

mod jsasm;
pub use jsasm::*;

mod wrap;
pub use wrap::*;

mod mac;
pub use mac::*;

mod sign;
pub use sign::*;

use clap::Parser;

#[derive(Debug, Parser)]
pub enum Args {
    Hash(ArgsHash),
    Rand(ArgsRand),
    Enc(ArgsEnc),
    Dec(ArgsDec),
    Kdf(ArgsKdf),
    /// AES Key Wrap / Unwrap (RFC 3394 / 5649).
    Wrap(ArgsWrap),
    /// FF1 format-preserving encryption (decimal).
    Ff1(ArgsFf1),
    /// Message authentication codes.
    Mac(ArgsMac),
    /// HOTP / TOTP one-time passwords.
    Otp(ArgsOtp),
    /// Digital signatures (Ed25519/Ed448).
    Sign(ArgsSign),
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
