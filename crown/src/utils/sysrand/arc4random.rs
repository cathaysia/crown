#![cfg(any(target_os = "macos", target_os = "openbsd"))]

unsafe extern "C" {
    fn arc4random_buf(buf: *mut core::ffi::c_void, nbytes: libc::size_t);
}

pub fn read(b: &mut [u8]) -> std::io::Result<()> {
    unsafe {
        arc4random_buf(b.as_mut_ptr() as *mut core::ffi::c_void, b.len());
    }
    Ok(())
}
