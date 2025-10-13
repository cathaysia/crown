/// XORBytes sets `x[i] = x[i] ^ y[i]` for all `i < n = min(len(x), len(y))`,
/// returning n, the number of bytes written to dst.
///
/// If dst does not have length at least n,
/// XORBytes panics without writing anything to dst.
///
/// dst and x or y may overlap exactly o
pub fn xor_bytes(x: &mut [u8], y: &[u8]) -> usize {
    let n = x.len().min(y.len());

    x.iter_mut().zip(y).take(n).for_each(|(x, y)| *x ^= y);

    n
}

#[allow(dead_code)]
pub fn xor_bytes_self(x: &mut [u8]) -> usize {
    x.iter_mut().for_each(|x| *x ^= *x);

    x.len()
}
