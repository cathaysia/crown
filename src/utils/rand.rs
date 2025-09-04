pub fn fill(b: &mut [u8]) {
    super::drbg::read(b);
}

pub fn random<T>() -> T
where
    T: Sized,
{
    let mut uninit = core::mem::MaybeUninit::uninit();
    let ptr = uninit.as_mut_ptr() as *mut u8;
    let s = unsafe { core::slice::from_raw_parts_mut(ptr, size_of::<T>()) };
    fill(s);
    unsafe { uninit.assume_init() }
}
