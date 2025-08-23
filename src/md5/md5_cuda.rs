use std::ptr::null_mut;

use crate::cuda::sys::cudaStream_t;

extern "C" {
    fn md5_sum_batch(
        count: u32,
        file_sizes: *const u32,
        data: *const u8,
        output: *mut u8,
        stream: cudaStream_t,
    );
}

pub fn md5_sum_batch_cuda(data: &[u8], file_siezs: &[u32], output: &mut [u8]) {
    unsafe {
        md5_sum_batch(
            file_siezs.len() as u32,
            file_siezs.as_ptr(),
            data.as_ptr(),
            output.as_mut_ptr(),
            null_mut(),
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_md5() {
        let data = b"hello world";
        let mut md5 = [0u8; 16];
        md5_sum_batch_cuda(data, &[data.len() as u32], md5.as_mut_slice());
        let md5_soft = super::super::sum(data);
        assert_eq!(&md5, &md5_soft)
    }
}
