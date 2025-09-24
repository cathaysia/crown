use std::{
    fs::File,
    io::Write,
    marker::PhantomData,
    os::{
        fd::{AsRawFd, FromRawFd},
        raw::c_void,
    },
    ptr::null_mut,
};

use anyhow::bail;
use libc::{MADV_DONTNEED, MADV_SEQUENTIAL, MAP_FAILED, MAP_SHARED, PROT_READ};
use nix::errno::Errno;

pub(crate) struct MmapRead;
pub(crate) struct MmapWrite;

pub struct MmapFile<T> {
    file: File,
    len: usize,
    ptr: *mut c_void,
    marker: PhantomData<T>,
}

impl AsMut<[u8]> for MmapFile<MmapWrite> {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

impl Write for MmapFile<MmapWrite> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl AsRef<[u8]> for MmapFile<MmapRead> {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast::<u8>(), self.len) }
    }
}

impl<T> Drop for MmapFile<T> {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

pub fn mmap_writer(file_path: &str, size: usize) -> anyhow::Result<MmapFile<MmapWrite>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .create(true)
        .open(file_path)?;
    let fd = file.as_raw_fd();
    let x = unsafe { libc::ftruncate(fd, size as _) };
    if x != 0 {
        return Err(anyhow::anyhow!(format!(
            "preallocate file failed: {}",
            Errno::last()
        )));
    }
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size as _,
            libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == MAP_FAILED {
        bail!("failed mmap file: {}", Errno::last());
    }
    unsafe { libc::madvise(ptr, size, MADV_SEQUENTIAL | MADV_DONTNEED) };
    Ok(MmapFile {
        file,
        len: size,
        ptr,
        marker: PhantomData,
    })
}

pub fn read_file_impl(file_path: &str) -> anyhow::Result<MmapFile<MmapRead>> {
    let file = if file_path == "-" {
        // TODO: is this safe?
        let fd = std::io::stdin().as_raw_fd();
        unsafe { File::from_raw_fd(fd) }
    } else {
        File::open(file_path)?
    };
    let file_size = file.metadata()?.len();
    let fd = file.as_raw_fd();

    let ptr = unsafe { libc::mmap(null_mut(), file_size as _, PROT_READ, MAP_SHARED, fd, 0) };
    if ptr == MAP_FAILED {
        bail!("failed mmap file: {}", Errno::last());
    }

    unsafe { libc::madvise(ptr, file_size as usize, MADV_SEQUENTIAL) };

    Ok(MmapFile {
        file,
        len: file_size as _,
        ptr,
        marker: PhantomData,
    })
}
