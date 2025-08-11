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

/// constant_time_eq returns true if the two slices, x and y, have equal contents
/// and false otherwise. The time taken is a function of the length of the slices and
/// is independent of the contents.
#[inline(always)]
pub fn constant_time_eq(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false;
    }

    let mut v = 0u8;
    for i in 0..x.len() {
        v |= x[i] ^ y[i];
    }

    v == 0
}
