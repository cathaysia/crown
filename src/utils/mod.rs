#[cfg(feature = "std")]
pub mod rand;
pub mod subtle;

#[cfg(feature = "std")]
pub(crate) mod drbg;
#[cfg(feature = "std")]
pub(crate) mod entropy;
#[cfg(feature = "std")]
pub(crate) mod randutil;
#[cfg(feature = "std")]
pub(crate) mod sysrand;

pub(crate) fn inexact_overlap(dst: &[u8], src: &[u8]) -> bool {
    let dst_ptr = dst.as_ptr() as usize;
    let src_ptr = src.as_ptr() as usize;
    let dst_end = dst_ptr + dst.len();
    let src_end = src_ptr + src.len();

    (dst_ptr < src_end && src_ptr < dst_end) && (dst_ptr != src_ptr)
}

pub fn copy(dst: &mut [u8], src: &[u8]) -> usize {
    let len = dst.len().min(src.len());
    dst[..len].copy_from_slice(&src[..len]);
    len
}

/// Check if two slices have any overlap in memory
pub fn any_overlap(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }

    let a_start = a.as_ptr() as usize;
    let a_end = a_start + a.len();
    let b_start = b.as_ptr() as usize;
    let b_end = b_start + b.len();

    !(a_end <= b_start || b_end <= a_start)
}
