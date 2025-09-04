pub fn fill(b: &mut [u8]) {
    crate::internal::drbg::read(b);
}
