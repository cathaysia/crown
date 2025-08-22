use std::{ffi::c_void, ptr::null_mut};

use crate::cuda::{
    error::{CudaError, CudaResult},
    sys,
};

pub struct PinedMemory {
    ptr: *mut c_void,
    len: usize,
}

impl Drop for PinedMemory {
    fn drop(&mut self) {
        unsafe {
            sys::cudaFreeHost(self.ptr);
        }
    }
}

impl PinedMemory {
    pub fn new(len: usize) -> CudaResult<Self> {
        let mut ptr = std::ptr::null_mut();
        let err = unsafe { sys::cudaMallocHost(&mut ptr, len) };
        CudaError::from(err).into_error(Self { ptr, len })
    }

    pub fn device_ptr(&self) -> CudaResult<*mut c_void> {
        unsafe {
            let mut dst = null_mut();
            let ptr = sys::cudaHostGetDevicePointer(&mut dst, self.ptr, 0);
            CudaError::from(ptr).into_error(dst)
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

impl TryFrom<&[u8]> for PinedMemory {
    type Error = CudaError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut v = Self::new(value.len())?;
        v.as_mut_slice().copy_from_slice(value);
        Ok(v)
    }
}
