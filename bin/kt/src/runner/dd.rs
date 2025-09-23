use std::io::Write;

use crate::args::ArgsDd;
use crate::size_parser::parse_size;

pub fn run_dd(args: ArgsDd) -> anyhow::Result<()> {
    let ArgsDd { bs, count, of } = args;
    let bs = parse_size(&bs)?;

    let mut output: Box<dyn Write> = if let Some(output_file) = of {
        Box::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(output_file)?,
        )
    } else {
        Box::new(std::io::stdout())
    };

    let mut buffer = vec![0u8; bs];
    let mut blocks_copied = 0;

    while blocks_copied < count {
        kittycrypto::rand::fill(&mut buffer);

        output.write_all(&buffer)?;
        blocks_copied += 1;
    }

    output.flush()?;
    Ok(())
}
