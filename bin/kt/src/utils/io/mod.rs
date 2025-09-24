mod fallback;
#[cfg(unix)]
mod unix;

pub fn read_file<'b>(file_path: &'_ str) -> anyhow::Result<impl AsRef<[u8]> + 'b> {
    #[cfg(unix)]
    return unix::read_file_impl(file_path);
    #[cfg(not(unix))]
    fallback::read_file_impl(file_path)
}

#[cfg(unix)]
pub fn write_file<'b>(file_path: &'_ str, size: usize) -> anyhow::Result<impl AsMut<[u8]> + 'b> {
    unix::mmap_writer(file_path, size)
}
