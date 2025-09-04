use crate::utils::inexact_overlap;

/// XORBytes sets `x[i] = x[i] ^ y[i]` for all `i < n = min(len(x), len(y))`,
/// returning n, the number of bytes written to dst.
///
/// If dst does not have length at least n,
/// XORBytes panics without writing anything to dst.
///
/// dst and x or y may overlap exactly o
pub fn xor_bytes(x: &mut [u8], y: &[u8]) -> usize {
    let n = x.len().min(y.len());
    if inexact_overlap(&x[..n], &y[..n]) {
        panic!("overlapping slices");
    }

    for i in 0..n {
        x[i] ^= y[i];
    }

    n
}

pub fn xor_bytes_self(x: &mut [u8]) -> usize {
    (0..x.len()).for_each(|i| {
        x[i] ^= x[i];
    });

    x.len()
}
