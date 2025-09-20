use std::io::Read;

mod fallback;
#[cfg(target_os = "linux")]
mod unix;

pub fn read_file<'b>(file_path: &'_ str) -> anyhow::Result<impl AsRef<[u8]> + 'b> {
    if file_path == "-" {
        let mut buf = vec![];
        std::io::stdin().read_to_end(&mut buf)?;
        buf.remove(buf.len() - 1);
        return Ok(buf);
    }
    #[cfg(target_os = "linux")]
    return unix::read_file_impl(file_path);
    #[cfg(not(target_os = "linux"))]
    fallback::read_file_impl(file_path)
}
