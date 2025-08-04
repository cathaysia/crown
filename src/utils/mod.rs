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
