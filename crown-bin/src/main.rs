#[cfg(feature = "cuda")]
mod cuda;
mod size_parser;
mod utils;

mod runner;

use crate::runner::hash::calc_and_output_hash;
use clap::Parser;
use tracing::*;
use utils::init_logger;

mod args;

const BIN_NAME: &str = "crown";

fn main() -> anyhow::Result<()> {
    init_logger();

    let prog = std::env::args().next();
    let prog = {
        prog.and_then(|prog| {
            let path = std::path::Path::new(&prog);
            path.file_stem().map(|v| v.to_string_lossy().to_string())
        })
        .unwrap_or("md5sum".into())
        .to_lowercase()
    };
    if prog != BIN_NAME {
        return main_mock(&prog);
    }

    let args = args::Args::parse();
    trace!(?args);
    match args {
        args::Args::Hash(args_hash) => runner::run_hash(args_hash)?,
        args::Args::Rand(args_rand) => runner::rand::run_rand(args_rand)?,
        args::Args::Enc(args) => runner::run_enc(args)?,
        args::Args::Dec(args) => runner::run_dec(args)?,
        args::Args::Kdf(args) => runner::run_kdf(args)?,
    }

    Ok(())
}

fn main_mock(prog: &str) -> anyhow::Result<()> {
    debug!("mock as {prog}");
    let arg = args::Md5::parse();
    calc_and_output_hash(prog.parse()?, arg.files, false, None, None);

    Ok(())
}
