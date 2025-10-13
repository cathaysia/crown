pub fn fill(b: &mut [u8]) {
    super::drbg::read(b);
}

#[allow(dead_code)]
pub trait Random: Sized {
    fn random() -> Self;
}

#[allow(dead_code)]
pub fn random<T>() -> T
where
    T: Random,
{
    T::random()
}

/// # Safety
///
/// use this function by your own risk.
pub unsafe fn unsafe_random<T>() -> T
where
    T: Sized,
{
    let mut uninit = core::mem::MaybeUninit::uninit();
    let ptr = uninit.as_mut_ptr() as *mut u8;
    let s = unsafe { core::slice::from_raw_parts_mut(ptr, size_of::<T>()) };
    fill(s);
    unsafe { uninit.assume_init() }
}

macro_rules! impl_random_for {
    (#inner $t: ty) => {
        impl Random for $t {
            fn random() -> Self {
                unsafe { unsafe_random() }
            }
        }
    };
    ($($ty:ty),* $(,)?) => {
        $(impl_random_for!(#inner $ty);)*
    }
}

impl_random_for!(i8, u8, i16, u16, i32, u32, i64, u64, f32, f64);
