use std::io::Write;

use base64::Engine;

use crate::{args::ArgsRand, size_parser::parse_size};

pub fn run_rand(args_hash: ArgsRand) -> anyhow::Result<()> {
    let ArgsRand {
        hex,
        base64,
        out,
        size,
    } = args_hash;
    let size = parse_size(&size)?;

    let mut out: Box<dyn Write> = if let Some(out) = out {
        #[cfg(unix)]
        {
            let mut file = crate::utils::write_file(&out, size)?;
            let buffer = file.as_mut();
            crown::rand::fill(buffer);
            return Ok(());
        }
        #[cfg(not(unix))]
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

    let mut buf = vec![0u8; size];
    crown::rand::fill(buf.as_mut_slice());
    if hex {
        write!(out, "{}", hex::encode(&buf)).unwrap();
    } else if base64 {
        write!(out, "{}", base64::prelude::BASE64_STANDARD.encode(&buf)).unwrap();
    } else {
        out.write_all(&buf).unwrap();
    };

    Ok(())
}
