use clap::Parser;

#[derive(Debug, Parser)]
pub struct ArgsDd {
    #[clap(long, default_value = "512")]
    pub bs: String,
    #[clap(long, default_value_t = 1)]
    pub count: usize,
    #[clap(long)]
    pub of: Option<String>,
}
