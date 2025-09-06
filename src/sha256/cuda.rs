//! CUDA implementation of SHA256 hash algorithm

use core::ptr::null_mut;

use crate::cuda::{
    self,
    error::{CudaError, CudaResult},
    mem::CudaMemory,
    sys::{cudaError, cudaStream_t},
};

extern "C" {
    fn sha256_sum_batch(
        count: u32,
        file_sizes: *const u32,
        file_offsets: *const u32,
        data: *const u8,
        output: *mut u8,
        stream: cudaStream_t,
    ) -> cudaError;
}

pub fn sha256_sum_batch_cuda(
    data: &CudaMemory<u8>,
    file_sizes: &CudaMemory<u32>,
    file_offsets: &CudaMemory<u32>,
    output: &mut CudaMemory,
) -> CudaResult<()> {
    unsafe {
        let err = sha256_sum_batch(
            file_sizes.len() as u32,
            file_sizes.device_ptr().unwrap().cast(),
            file_offsets.device_ptr().unwrap().cast(),
            data.device_ptr().unwrap().cast(),
            output.device_ptr().unwrap(),
            null_mut(),
        );
        CudaError::from(err).into_error(())?;
        cuda::sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn test_cuda_sha256() {
        let data = b"hello world";
        let sha256_cuda = {
            let data = CudaMemory::from_slice_to_device(data).unwrap();
            let file_sizes = CudaMemory::from_slice_to_device(&[data.len() as u32]).unwrap();
            let file_offsets = CudaMemory::from_slice_to_device(&[0]).unwrap();
            let mut sha256 = CudaMemory::<u8>::new_pined(32).unwrap();
            sha256_sum_batch_cuda(&data, &file_sizes, &file_offsets, &mut sha256).unwrap();
            sha256.to_vec().unwrap()
        };
        let sha256_soft = sha256::sum256(data);
        assert_eq!(&sha256_cuda, &sha256_soft);

        for _ in 0..1000 {
            let len: usize = rand::random_range(0..4096);
            let mut data = vec![0u8; len];
            rand::fill(data.as_mut_slice());
            let sum_soft = sha256::sum256(&data);

            let sum_cuda = {
                let data = CudaMemory::from_slice_to_device(&data).unwrap();
                let file_sizes = CudaMemory::from_slice_to_device(&[data.len() as u32]).unwrap();
                let file_offsets = CudaMemory::from_slice_to_device(&[0]).unwrap();
                let mut sha256 = CudaMemory::<u8>::new_pined(32).unwrap();
                sha256_sum_batch_cuda(&data, &file_sizes, &file_offsets, &mut sha256).unwrap();
                sha256.to_vec().unwrap()
            };

            assert_eq!(&sum_soft, sum_cuda.as_slice());
        }
    }
}
