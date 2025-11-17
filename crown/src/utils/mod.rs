pub mod cpuid;
#[cfg(feature = "std")]
pub mod rand;
pub mod subtle;

#[cfg(feature = "std")]
pub(crate) mod drbg;
#[cfg(feature = "std")]
pub(crate) mod entropy;
#[cfg(feature = "std")]
pub(crate) mod randutil;
#[cfg(feature = "std")]
pub(crate) mod sysrand;

pub(crate) fn copy(dst: &mut [u8], src: &[u8]) -> usize {
    let len = dst.len().min(src.len());
    dst[..len].copy_from_slice(&src[..len]);
    len
}

/// Check if two slices have any overlap in memory
pub(crate) fn any_overlap(a: &[u8], b: &[u8]) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }

    let a_start = a.as_ptr() as usize;
    let a_end = a_start + a.len();
    let b_start = b.as_ptr() as usize;
    let b_end = b_start + b.len();

    !(a_end <= b_start || b_end <= a_start)
}

/// Creates a new slice from the given slice without transferring ownership.
///
/// This function reinterprets the lifetime of the input slice to a new lifetime `'a`,
/// effectively allowing the slice to be used in contexts where a different lifetime
/// is required. The caller must ensure that the returned reference does not outlive
/// the original data.
///
/// # Safety
///
/// The caller must ensure that the returned reference is not used after the original
/// data is deallocated or moved.
///
/// # Parameters
///
/// * `slice` - A reference to the original slice.
///
/// # Returns
///
/// A new slice with the same data and length but with a different ownership.
pub unsafe fn erase_ownership<'a, T>(slice: &[T]) -> &'a [T] {
    let ptr = slice.as_ptr();
    unsafe { core::slice::from_raw_parts(ptr, slice.len()) }
}

/// Creates a new slice from the given slice without transferring ownership.
///
/// This function reinterprets the lifetime of the input slice to a new lifetime `'a`,
/// effectively allowing the slice to be used in contexts where a different lifetime
/// is required. The caller must ensure that the returned reference does not outlive
/// the original data.
///
/// # Safety
///
/// The caller must ensure that the returned reference is not used after the original
/// data is deallocated or moved.
///
/// # Parameters
///
/// * `slice` - A mut reference to the original slice.
///
/// # Returns
///
/// A new slice with the same data and length but with a different lifetime.
pub(crate) unsafe fn erase_ownership_mut<'a, T>(slice: &mut [T]) -> &'a mut [T] {
    let ptr = slice.as_mut_ptr();
    unsafe { core::slice::from_raw_parts_mut(ptr, slice.len()) }
}
