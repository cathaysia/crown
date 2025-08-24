use std::ptr::null_mut;

use crate::cuda::{
    error::{CudaError, CudaResult},
    sys,
};

pub struct PinedMemory<T = u8> {
    ptr: *mut T,
    /// Count of T
    len: usize,
}

impl<T> Drop for PinedMemory<T> {
    fn drop(&mut self) {
        unsafe {
            sys::cudaFreeHost(self.ptr.cast());
        }
    }
}

impl<T> PinedMemory<T> {
    pub fn new(len: usize) -> CudaResult<Self> {
        let mut ptr = std::ptr::null_mut();
        let err = unsafe { sys::cudaMallocHost(&mut ptr, len * size_of::<T>()) };
        CudaError::from(err).into_error(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    pub fn device_ptr(&self) -> CudaResult<*mut T> {
        unsafe {
            let mut dst = null_mut();
            let ptr = sys::cudaHostGetDevicePointer(&mut dst, self.ptr.cast(), 0);
            CudaError::from(ptr).into_error(dst.cast())
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) }
    }
}

impl<T: Copy> TryFrom<&[T]> for PinedMemory<T> {
    type Error = CudaError;

    fn try_from(value: &[T]) -> Result<Self, Self::Error> {
        let mut v = Self::new(value.len())?;
        v.as_mut_slice().copy_from_slice(value);
        Ok(v)
    }
}
