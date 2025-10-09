#![allow(clippy::missing_safety_doc)]

pub mod evp_aead;
pub mod evp_block;
pub mod evp_hash;
pub mod evp_stream;

unsafe fn slice_from_raw_parts<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        None
    } else {
        unsafe { Some(std::slice::from_raw_parts(ptr, len)) }
    }
}

unsafe fn option_from_ptr<T>(ptr: *const T) -> Option<T>
where
    T: Copy,
{
    if ptr.is_null() {
        None
    } else {
        unsafe { Some(*ptr) }
    }
}
