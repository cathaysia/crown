pub mod xor;
#[cfg(feature = "cuda")]
pub mod xor_gpu;

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
