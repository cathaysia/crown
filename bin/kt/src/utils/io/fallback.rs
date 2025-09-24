#![allow(dead_code)]

pub fn read_file_impl(file_path: &str) -> anyhow::Result<Vec<u8>> {
    Ok(std::fs::read(file_path)?)
}
