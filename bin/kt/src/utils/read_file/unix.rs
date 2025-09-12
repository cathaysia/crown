use std::{
    fs::File,
    os::{fd::AsRawFd, raw::c_void},
    ptr::null_mut,
};

use anyhow::bail;
use libc::{MADV_SEQUENTIAL, MAP_FAILED, MAP_SHARED, PROT_READ};

pub struct MmapFile {
    len: usize,
    ptr: *mut c_void,
}

impl AsRef<[u8]> for MmapFile {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
    }
}

impl Drop for MmapFile {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

pub fn read_file_impl(file_path: &str) -> anyhow::Result<MmapFile> {
    let file = File::open(file_path)?;
    let fd = file.as_raw_fd();
    let file_size = file.metadata()?.len();

    let ptr = unsafe { libc::mmap(null_mut(), file_size as _, PROT_READ, MAP_SHARED, fd, 0) };
    if ptr == MAP_FAILED {
        bail!("failed mmap file");
    }

    unsafe { libc::madvise(ptr, file_size as usize, MADV_SEQUENTIAL) };

    Ok(MmapFile {
        len: file_size as _,
        ptr,
    })
}
