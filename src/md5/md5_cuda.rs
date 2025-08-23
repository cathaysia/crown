use std::ptr::null_mut;

use crate::cuda::{
    error::{CudaError, CudaResult},
    sys::{cudaError, cudaStream_t},
};

extern "C" {
    fn md5_sum_batch(
        count: u32,
        file_sizes: *const u32,
        data: *const u8,
        output: *mut u8,
        stream: cudaStream_t,
    ) -> cudaError;
}

pub fn md5_sum_batch_cuda(data: &[u8], file_siezs: &[u32], output: &mut [u8]) -> CudaResult<()> {
    unsafe {
        let err = md5_sum_batch(
            file_siezs.len() as u32,
            file_siezs.as_ptr(),
            data.as_ptr(),
            output.as_mut_ptr(),
            null_mut(),
        );
        CudaError::from(err).into_error(())
    }
}

#[cfg(test)]
mod test {
    use super::super::tests::GOLDEN;
    use super::*;

    #[test]
    fn test_cuda_golden() {
        for (i, test) in GOLDEN.iter().enumerate() {
            let mut md5 = [0u8; 16];
            md5_sum_batch_cuda(
                test.input.as_bytes(),
                &[test.input.len() as u32],
                md5.as_mut_slice(),
            )
            .unwrap();
            let md5 = hex::encode(md5);
            assert_eq!(md5, test.out, "test {i} failed");
        }
    }

    #[test]
    fn test_md5() {
        let data = b"hello world";
        let mut md5 = [0u8; 16];
        md5_sum_batch_cuda(data, &[data.len() as u32], md5.as_mut_slice()).unwrap();
        let md5_soft = super::super::sum(data);
        assert_eq!(&md5, &md5_soft);

        for _ in 0..1000 {
            let len: usize = rand::random_range(0..4096);
            let mut data = vec![0u8; len];
            rand::fill(data.as_mut_slice());
            let sum_soft = super::super::sum(&data);

            let mut sum_cuda = [0u8; 16];
            md5_sum_batch_cuda(&data, &[len as u32], &mut sum_cuda).unwrap();

            assert_eq!(sum_soft, sum_cuda);
        }
    }
}
