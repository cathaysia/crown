#include <cuda_runtime.h>
#include <stdint.h>

__global__ void xor_bytes_kernel(uint8_t* inout, const uint8_t* in, uintptr_t size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if(idx < size) {
        inout[idx] ^= in[idx];
    }
}

extern "C" cudaError xor_bytes(uint8_t* inout, const uint8_t* in, uintptr_t size) {
    if(size == 0) {
        return cudaError::cudaSuccess;
    }

    cudaGetErrorString(cudaError_t::cudaSuccess);

    int threadsPerBlock = 256;
    int blocksPerGrid = (size + threadsPerBlock - 1) / threadsPerBlock;

    xor_bytes_kernel<<<blocksPerGrid, threadsPerBlock>>>(inout, in, size);

    return cudaGetLastError();
}
