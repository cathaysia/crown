use core::{ffi::c_void, ptr::null_mut};

use crate::cuda::{
    error::{CudaError, CudaResult},
    sys,
};

pub struct DeviceMemory<T = u8> {
    ptr: *mut T,
    /// Count of T
    len: usize,
}

impl<T> Drop for DeviceMemory<T> {
    fn drop(&mut self) {
        unsafe {
            sys::cudaFree(self.ptr.cast());
        }
    }
}

impl<T> DeviceMemory<T> {
    pub fn new(len: usize) -> CudaResult<Self> {
        unsafe {
            let mut ptr = null_mut();
            let err = sys::cudaMalloc(&mut ptr, len * size_of::<T>());

            CudaError::from(err).into_error(Self {
                ptr: ptr.cast(),
                len,
            })
        }
    }

    pub fn device_ptr(&self) -> *mut T {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<T: Copy> DeviceMemory<T> {
    #[allow(clippy::manual_slice_size_calculation)]
    pub fn copy_from_slice(&mut self, src: &[T]) -> CudaResult<()> {
        if src.len() != self.len {
            return Err(CudaError::InvalidValue);
        }

        unsafe {
            let err = sys::cudaMemcpy(
                self.ptr.cast(),
                src.as_ptr() as *const c_void,
                src.len() * size_of::<T>(),
                sys::cudaMemcpyKind::cudaMemcpyHostToDevice,
            );
            CudaError::from(err).into_error(())
        }
    }

    pub fn copy_to_slice(&self, dst: &mut [T]) -> CudaResult<()> {
        if dst.len() != self.len {
            return Err(CudaError::InvalidValue);
        }

        unsafe {
            let err = sys::cudaMemcpy(
                dst.as_mut_ptr() as *mut c_void,
                self.ptr.cast(),
                self.len * size_of::<T>(),
                sys::cudaMemcpyKind::cudaMemcpyDeviceToHost,
            );

            CudaError::from(err).into_error(())
        }
    }
}

impl<T: Copy> TryFrom<&[T]> for DeviceMemory<T> {
    type Error = CudaError;
    fn try_from(value: &[T]) -> Result<Self, Self::Error> {
        let mut v = Self::new(value.len())?;
        v.copy_from_slice(value)?;
        Ok(v)
    }
}
