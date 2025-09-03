use std::io::Write;

use base64::Engine;

use crate::args::ArgsRand;

pub fn run_hash(args_hash: ArgsRand) -> anyhow::Result<()> {
    let ArgsRand {
        hex,
        base64,
        out,
        num,
    } = args_hash;

    let mut buf = vec![0u8; num];
    kittycrypto::internal::drbg::read(buf.as_mut_slice());
    let mut out: Box<dyn Write> = if let Some(out) = out {
        Box::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(out)
                .unwrap(),
        )
    } else {
        Box::new(std::io::stdout())
    };

    if hex {
        write!(out, "{}", hex::encode(&buf)).unwrap();
    } else if base64 {
        write!(out, "{}", base64::prelude::BASE64_STANDARD.encode(&buf)).unwrap();
    } else {
        out.write_all(&buf).unwrap();
    };

    Ok(())
}
