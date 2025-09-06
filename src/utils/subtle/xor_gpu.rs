use crate::cuda::mem::CudaMemory;

extern "C" {
    fn xor_bytes(x: *mut u8, y: *const u8, n: usize) -> crate::cuda::sys::cudaError;
}

pub fn xor_bytes_cuda(x: &mut CudaMemory, y: &CudaMemory) -> usize {
    let n = x.len().min(y.len());

    unsafe {
        xor_bytes(
            x.device_ptr().unwrap().cast(),
            y.device_ptr().unwrap().cast(),
            n,
        );
    }

    n
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gpu_xor() {
        let mut x = [0u8; 1024];
        let mut y = [0u8; 1024];
        rand::fill(&mut x);
        rand::fill(&mut y);

        let mut xcpu = x;
        crate::utils::subtle::xor::xor_bytes(&mut xcpu, &y);

        let mut xc = CudaMemory::from_slice_to_device(&x).unwrap();
        let yc = CudaMemory::from_slice_to_device(&y).unwrap();
        assert_eq!(xc.len(), x.len());
        xor_bytes_cuda(&mut xc, &yc);

        let xcuda = xc.to_vec().unwrap();
        assert_eq!(xcuda, xcpu);
    }
}
