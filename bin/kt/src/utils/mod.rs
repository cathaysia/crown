mod read_file;

pub use read_file::read_file;

pub fn init_logger() {
    use tracing_subscriber::{fmt, prelude::*, util::SubscriberInitExt, EnvFilter};

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_writer(std::io::stderr),
        )
        .with(EnvFilter::from_default_env())
        .init();
}
