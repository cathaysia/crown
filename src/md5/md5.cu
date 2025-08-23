/**
 * CUDA implementation of MD5 hash algorithm for batch processing of files.
 * This implementation is based on the MD5 implementation in the project.
 *
 * Note: When compiling with CUDA 13.0 or newer, use the following flags:
 * --cuda-gpu-arch=sm_70 or --no-cuda-version-check
 */

// This code is compatible with CUDA 13.0, but requires specific compilation flags
// Use: nvcc --cuda-gpu-arch=sm_70 or nvcc --no-cuda-version-check

#include <cuda_runtime.h>
#include <stdint.h>

// MD5 constants
#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

// MD5 initial values
#define INIT0 0x67452301u
#define INIT1 0xEFCDAB89u
#define INIT2 0x98BADCFEu
#define INIT3 0x10325476u

// Helper functions for MD5 algorithm
__device__ uint32_t le_u32(const uint8_t* b) {
    return ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

__device__ void le_put_u32(uint8_t* b, uint32_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

__device__ void le_put_u64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v);
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
    b[4] = (uint8_t)(v >> 32);
    b[5] = (uint8_t)(v >> 40);
    b[6] = (uint8_t)(v >> 48);
    b[7] = (uint8_t)(v >> 56);
}

// CUDA extension for rotate left
__device__ __forceinline__ uint32_t rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

// MD5 round functions
__device__ __forceinline__ uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
    return (z ^ (x & (y ^ z)));
}

__device__ __forceinline__ uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
    return (y ^ (z & (x ^ y)));
}

__device__ __forceinline__ uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
    return (x ^ y ^ z);
}

__device__ __forceinline__ uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
    return (y ^ (x | ~z));
}

// MD5 state structure
typedef struct {
    uint32_t s[4];
    uint8_t x[MD5_BLOCK_SIZE];
    uint32_t nx;
    uint64_t len;
} Md5Digest;

// Initialize MD5 context
__device__ void md5_init(Md5Digest* self) {
    self->s[0] = INIT0;
    self->s[1] = INIT1;
    self->s[2] = INIT2;
    self->s[3] = INIT3;
    self->nx = 0;
    self->len = 0;
}

// Process a block of data
__device__ void md5_block_process(Md5Digest* self, const uint8_t* block) {
    uint32_t a = self->s[0];
    uint32_t b = self->s[1];
    uint32_t c = self->s[2];
    uint32_t d = self->s[3];

    uint32_t x[16];
    for(int i = 0; i < 16; i++) {
        x[i] = le_u32(&block[i * 4]);
    }

    // Round 1
    a = b + rotl((((c ^ d) & b) ^ d) + a + x[0] + 0xd76aa478, 7);
    d = a + rotl((((b ^ c) & a) ^ c) + d + x[1] + 0xe8c7b756, 12);
    c = d + rotl((((a ^ b) & d) ^ b) + c + x[2] + 0x242070db, 17);
    b = c + rotl((((d ^ a) & c) ^ a) + b + x[3] + 0xc1bdceee, 22);
    a = b + rotl((((c ^ d) & b) ^ d) + a + x[4] + 0xf57c0faf, 7);
    d = a + rotl((((b ^ c) & a) ^ c) + d + x[5] + 0x4787c62a, 12);
    c = d + rotl((((a ^ b) & d) ^ b) + c + x[6] + 0xa8304613, 17);
    b = c + rotl((((d ^ a) & c) ^ a) + b + x[7] + 0xfd469501, 22);
    a = b + rotl((((c ^ d) & b) ^ d) + a + x[8] + 0x698098d8, 7);
    d = a + rotl((((b ^ c) & a) ^ c) + d + x[9] + 0x8b44f7af, 12);
    c = d + rotl((((a ^ b) & d) ^ b) + c + x[10] + 0xffff5bb1, 17);
    b = c + rotl((((d ^ a) & c) ^ a) + b + x[11] + 0x895cd7be, 22);
    a = b + rotl((((c ^ d) & b) ^ d) + a + x[12] + 0x6b901122, 7);
    d = a + rotl((((b ^ c) & a) ^ c) + d + x[13] + 0xfd987193, 12);
    c = d + rotl((((a ^ b) & d) ^ b) + c + x[14] + 0xa679438e, 17);
    b = c + rotl((((d ^ a) & c) ^ a) + b + x[15] + 0x49b40821, 22);

    // Round 2
    a = b + rotl((((b ^ c) & d) ^ c) + a + x[1] + 0xf61e2562, 5);
    d = a + rotl((((a ^ b) & c) ^ b) + d + x[6] + 0xc040b340, 9);
    c = d + rotl((((d ^ a) & b) ^ a) + c + x[11] + 0x265e5a51, 14);
    b = c + rotl((((c ^ d) & a) ^ d) + b + x[0] + 0xe9b6c7aa, 20);
    a = b + rotl((((b ^ c) & d) ^ c) + a + x[5] + 0xd62f105d, 5);
    d = a + rotl((((a ^ b) & c) ^ b) + d + x[10] + 0x02441453, 9);
    c = d + rotl((((d ^ a) & b) ^ a) + c + x[15] + 0xd8a1e681, 14);
    b = c + rotl((((c ^ d) & a) ^ d) + b + x[4] + 0xe7d3fbc8, 20);
    a = b + rotl((((b ^ c) & d) ^ c) + a + x[9] + 0x21e1cde6, 5);
    d = a + rotl((((a ^ b) & c) ^ b) + d + x[14] + 0xc33707d6, 9);
    c = d + rotl((((d ^ a) & b) ^ a) + c + x[3] + 0xf4d50d87, 14);
    b = c + rotl((((c ^ d) & a) ^ d) + b + x[8] + 0x455a14ed, 20);
    a = b + rotl((((b ^ c) & d) ^ c) + a + x[13] + 0xa9e3e905, 5);
    d = a + rotl((((a ^ b) & c) ^ b) + d + x[2] + 0xfcefa3f8, 9);
    c = d + rotl((((d ^ a) & b) ^ a) + c + x[7] + 0x676f02d9, 14);
    b = c + rotl((((c ^ d) & a) ^ d) + b + x[12] + 0x8d2a4c8a, 20);

    // Round 3
    a = b + rotl((b ^ c ^ d) + a + x[5] + 0xfffa3942, 4);
    d = a + rotl((a ^ b ^ c) + d + x[8] + 0x8771f681, 11);
    c = d + rotl((d ^ a ^ b) + c + x[11] + 0x6d9d6122, 16);
    b = c + rotl((c ^ d ^ a) + b + x[14] + 0xfde5380c, 23);
    a = b + rotl((b ^ c ^ d) + a + x[1] + 0xa4beea44, 4);
    d = a + rotl((a ^ b ^ c) + d + x[4] + 0x4bdecfa9, 11);
    c = d + rotl((d ^ a ^ b) + c + x[7] + 0xf6bb4b60, 16);
    b = c + rotl((c ^ d ^ a) + b + x[10] + 0xbebfbc70, 23);
    a = b + rotl((b ^ c ^ d) + a + x[13] + 0x289b7ec6, 4);
    d = a + rotl((a ^ b ^ c) + d + x[0] + 0xeaa127fa, 11);
    c = d + rotl((d ^ a ^ b) + c + x[3] + 0xd4ef3085, 16);
    b = c + rotl((c ^ d ^ a) + b + x[6] + 0x04881d05, 23);
    a = b + rotl((b ^ c ^ d) + a + x[9] + 0xd9d4d039, 4);
    d = a + rotl((a ^ b ^ c) + d + x[12] + 0xe6db99e5, 11);
    c = d + rotl((d ^ a ^ b) + c + x[15] + 0x1fa27cf8, 16);
    b = c + rotl((c ^ d ^ a) + b + x[2] + 0xc4ac5665, 23);

    // Round 4
    a = b + rotl((c ^ (b | ~d)) + a + x[0] + 0xf4292244, 6);
    d = a + rotl((b ^ (a | ~c)) + d + x[7] + 0x432aff97, 10);
    c = d + rotl((a ^ (d | ~b)) + c + x[14] + 0xab9423a7, 15);
    b = c + rotl((d ^ (c | ~a)) + b + x[5] + 0xfc93a039, 21);
    a = b + rotl((c ^ (b | ~d)) + a + x[12] + 0x655b59c3, 6);
    d = a + rotl((b ^ (a | ~c)) + d + x[3] + 0x8f0ccc92, 10);
    c = d + rotl((a ^ (d | ~b)) + c + x[10] + 0xffeff47d, 15);
    b = c + rotl((d ^ (c | ~a)) + b + x[1] + 0x85845dd1, 21);
    a = b + rotl((c ^ (b | ~d)) + a + x[8] + 0x6fa87e4f, 6);
    d = a + rotl((b ^ (a | ~c)) + d + x[15] + 0xfe2ce6e0, 10);
    c = d + rotl((a ^ (d | ~b)) + c + x[6] + 0xa3014314, 15);
    b = c + rotl((d ^ (c | ~a)) + b + x[13] + 0x4e0811a1, 21);
    a = b + rotl((c ^ (b | ~d)) + a + x[4] + 0xf7537e82, 6);
    d = a + rotl((b ^ (a | ~c)) + d + x[11] + 0xbd3af235, 10);
    c = d + rotl((a ^ (d | ~b)) + c + x[2] + 0x2ad7d2bb, 15);
    b = c + rotl((d ^ (c | ~a)) + b + x[9] + 0xeb86d391, 21);

    // Add back to state
    self->s[0] += a;
    self->s[1] += b;
    self->s[2] += c;
    self->s[3] += d;
}

#define min(x, y) ((x) > (y) ? (y) : (x))

// Update MD5 context with new data
__device__ void md5_update(Md5Digest* self, const uint8_t* p, size_t len) {
    self->len += len;

    // Handle any remaining bytes from last update
    if(self->nx > 0) {
        uint32_t n = min(len, MD5_BLOCK_SIZE - self->nx);
        memcpy(&self->x[self->nx], p, n);
        self->nx += n;

        if(self->nx == MD5_BLOCK_SIZE) {
            md5_block_process(self, self->x);
            self->nx = 0;
        }

        p += n;
        len -= n;
    }

    if(len > MD5_BLOCK_SIZE) {
        size_t n = len & !(MD5_BLOCK_SIZE - 1);
        md5_block_process(self, p);
        p = p + n;
        len -= n;
    }

    if(len != 0) {
        self->nx = len;
        memcpy(self->x, p, self->nx);
    }
}

// Finalize MD5 calculation and get digest
__device__ void md5_final(Md5Digest* self, uint8_t* digest) {
    // Padding buffer - exactly match the original implementation
    uint8_t tmp[1 + 63 + 8] = { 0 };
    tmp[0] = 0x80;  // First bit is 1, rest are 0

    // Calculate padding length - exactly match the original implementation
    uint64_t pad = (55ULL - self->len) % 64;

    // Add length (in bits) - exactly match the original implementation
    le_put_u64(&tmp[1 + pad], self->len << 3);

    // Process padding and length
    md5_update(self, tmp, 1 + pad + 8);

    // Verify nx is 0, as in the original implementation
    if(self->nx != 0) {
        return;
    }

    // Get final digest
    le_put_u32(&digest[0], self->s[0]);
    le_put_u32(&digest[4], self->s[1]);
    le_put_u32(&digest[8], self->s[2]);
    le_put_u32(&digest[12], self->s[3]);
}

// Main kernel function to calculate MD5 for multiple files
__global__ void calculate_md5_kernel(
    const uint32_t count,
    const uint32_t* file_sizes,
    const uint32_t* file_offsets,  // Optional: Pre-calculated offsets for better performance
    const uint8_t* data,
    uint8_t* output
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if(idx >= count) {
        return;
    }

    // Calculate offset for this file's data
    uint64_t offset;
    if(file_offsets != nullptr) {
        // Use pre-calculated offset if provided
        offset = file_offsets[idx];
    } else {
        // Calculate offset on the fly
        offset = 0;
        for(uint32_t i = 0; i < idx; i++) {
            offset += file_sizes[i];
        }
    }

    // Initialize MD5 context
    Md5Digest ctx;
    md5_init(&ctx);

    // Process file data
    md5_update(&ctx, &data[offset], file_sizes[idx]);

    // Finalize and store result
    md5_final(&ctx, &output[idx * MD5_DIGEST_SIZE]);
}

// Helper function to launch the kernel
extern "C" cudaError_t md5_sum_batch(
    const uint32_t count,
    const uint32_t* file_sizes,
    const uint8_t* data,
    uint8_t* output,
    cudaStream_t stream = 0
) {
    cudaError_t err;

    // Calculate grid and block dimensions
    // Adjust based on GPU capabilities for better performance
    const int threadsPerBlock = 256;
    const int blocksPerGrid = (count + threadsPerBlock - 1) / threadsPerBlock;

    // Optional: Pre-calculate file offsets for better performance
    uint32_t* d_file_offsets = nullptr;
    if(count > 1000) {  // Only worth it for large batch sizes
        // Allocate device memory for offsets
        err = cudaMalloc(&d_file_offsets, count * sizeof(uint32_t));
        if(err != cudaSuccess) {
            return err;
        }

        // Create host array for offsets
        uint32_t* h_file_offsets = new uint32_t[count];
        if(!h_file_offsets) {
            cudaFree(d_file_offsets);
            return cudaErrorMemoryAllocation;
        }

        // Calculate offsets
        uint64_t offset = 0;
        for(uint32_t i = 0; i < count; i++) {
            h_file_offsets[i] = offset;
            offset += file_sizes[i];
        }

        // Copy offsets to device
        err = cudaMemcpy(d_file_offsets, h_file_offsets, count * sizeof(uint32_t), cudaMemcpyHostToDevice);
        delete[] h_file_offsets;

        if(err != cudaSuccess) {
            cudaFree(d_file_offsets);
            return err;
        }
    }

    // Launch kernel
    calculate_md5_kernel<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(
        count, file_sizes, d_file_offsets, data, output
    );

    // Free temporary memory
    if(d_file_offsets) {
        cudaFree(d_file_offsets);
    }

    // Check for kernel launch errors
    err = cudaGetLastError();
    if(err != cudaSuccess) {
        return err;
    }

    // Synchronize if no stream is provided
    if(stream == 0) {
        return cudaDeviceSynchronize();
    }

    return cudaSuccess;
}
