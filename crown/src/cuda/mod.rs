#![cfg(feature = "cuda")]

use crate::cuda::error::{CudaError, CudaResult};

pub mod mem;
pub(crate) mod sys;

pub mod error;

/// cudaDeviceSynchronize
pub fn sync() -> CudaResult<()> {
    let err = unsafe { sys::cudaDeviceSynchronize() };
    CudaError::from(err).into_error(())
}
