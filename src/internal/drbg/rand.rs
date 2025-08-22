use crate::internal::sysrand;

pub fn read(b: &mut [u8]) {
    sysrand::fill_bytes(b);
}
