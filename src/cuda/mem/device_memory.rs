use std::{ffi::c_void, ptr::null_mut};

use crate::cuda::{
    error::{CudaError, CudaResult},
    sys,
};

pub struct DeviceMemory {
    ptr: *mut c_void,
    len: usize,
}

impl Drop for DeviceMemory {
    fn drop(&mut self) {
        unsafe {
            sys::cudaFree(self.ptr);
        }
    }
}

impl DeviceMemory {
    pub fn new(len: usize) -> CudaResult<Self> {
        unsafe {
            let mut ptr = null_mut();
            let err = sys::cudaMalloc(&mut ptr, len);

            CudaError::from(err).into_error(Self { ptr, len })
        }
    }

    pub fn device_ptr(&self) -> *mut c_void {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn copy_from_slice(&mut self, src: &[u8]) -> CudaResult<()> {
        if src.len() != self.len {
            return Err(CudaError::InvalidValue);
        }

        unsafe {
            let err = sys::cudaMemcpy(
                self.ptr,
                src.as_ptr() as *const c_void,
                src.len(),
                sys::cudaMemcpyKind::cudaMemcpyHostToDevice,
            );
            CudaError::from(err).into_error(())
        }
    }

    pub fn copy_to_slice(&self, dst: &mut [u8]) -> CudaResult<()> {
        if dst.len() != self.len {
            return Err(CudaError::InvalidValue);
        }

        unsafe {
            let err = sys::cudaMemcpy(
                dst.as_mut_ptr() as *mut c_void,
                self.ptr,
                self.len,
                sys::cudaMemcpyKind::cudaMemcpyDeviceToHost,
            );

            CudaError::from(err).into_error(())
        }
    }
}

impl TryFrom<&[u8]> for DeviceMemory {
    type Error = CudaError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut v = Self::new(value.len())?;
        v.copy_from_slice(value)?;
        Ok(v)
    }
}
