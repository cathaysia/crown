use crate::utils::inexact_overlap;

/// XORBytes sets `dst[i] = x[i] ^ y[i]` for all `i < n = min(len(x), len(y))`,
/// returning n, the number of bytes written to dst.
///
/// If dst does not have length at least n,
/// XORBytes panics without writing anything to dst.
///
/// dst and x or y may overlap exactly o
pub fn xor_bytes(dst: &mut [u8], x: &[u8], y: &[u8]) -> usize {
    let n = x.len().min(y.len());
    if n > dst.len() {
        panic!("dst too short")
    }
    if inexact_overlap(&dst[..n], &x[..n]) || inexact_overlap(&dst[..n], &y[..n]) {
        panic!("overlapping slices");
    }

    for i in 0..n {
        dst[i] = x[i] ^ y[i];
    }

    n
}
