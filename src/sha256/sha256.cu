/**
 * CUDA implementation of SHA256 hash algorithm for batch processing of files.
 * This implementation is based on the SHA256 implementation in the project.
 *
 * Note: When compiling with CUDA 13.0 or newer, use the following flags:
 * --cuda-gpu-arch=sm_70 or --no-cuda-version-check
 */

// This code is compatible with CUDA 13.0, but requires specific compilation flags
// Use: nvcc --cuda-gpu-arch=sm_70 or nvcc --no-cuda-version-check

#include <cuda_runtime.h>
#include <stdint.h>

// SHA256 constants
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

// SHA256 initial values
#define INIT0 0x6A09E667u
#define INIT1 0xBB67AE85u
#define INIT2 0x3C6EF372u
#define INIT3 0xA54FF53Au
#define INIT4 0x510E527Fu
#define INIT5 0x9B05688Cu
#define INIT6 0x1F83D9ABu
#define INIT7 0x5BE0CD19u

// K constants for SHA256
__constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Helper functions for SHA256 algorithm
__device__ uint32_t be_u32(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | ((uint32_t)b[3]);
}

__device__ void be_put_u32(uint8_t* b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

__device__ void be_put_u64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)(v);
}

// CUDA extension for rotate right
__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// SHA256 functions
__device__ __forceinline__ uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ __forceinline__ uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint32_t Sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

__device__ __forceinline__ uint32_t Sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

__device__ __forceinline__ uint32_t sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA256 state structure
typedef struct {
    uint32_t h[8];
    uint8_t x[SHA256_BLOCK_SIZE];
    uint32_t nx;
    uint64_t len;
} Sha256Digest;

// Initialize SHA256 context
__device__ void sha256_init(Sha256Digest* self) {
    self->h[0] = INIT0;
    self->h[1] = INIT1;
    self->h[2] = INIT2;
    self->h[3] = INIT3;
    self->h[4] = INIT4;
    self->h[5] = INIT5;
    self->h[6] = INIT6;
    self->h[7] = INIT7;
    self->nx = 0;
    self->len = 0;
}

// Process a block of data
__device__ void sha256_block_process(Sha256Digest* self, const uint8_t* block, uintptr_t block_size) {
    uint32_t a = self->h[0];
    uint32_t b = self->h[1];
    uint32_t c = self->h[2];
    uint32_t d = self->h[3];
    uint32_t e = self->h[4];
    uint32_t f = self->h[5];
    uint32_t g = self->h[6];
    uint32_t h = self->h[7];

    for(uintptr_t i = 0; i + 64 <= block_size; i += 64) {
        uint32_t w[64];

        // Prepare message schedule
        for(int j = 0; j < 16; j++) {
            w[j] = be_u32(&block[i + j * 4]);
        }

        for(int j = 16; j < 64; j++) {
            w[j] = sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j - 16];
        }

        uint32_t aa = a;
        uint32_t bb = b;
        uint32_t cc = c;
        uint32_t dd = d;
        uint32_t ee = e;
        uint32_t ff = f;
        uint32_t gg = g;
        uint32_t hh = h;

        // Main loop
        for(int j = 0; j < 64; j++) {
            uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
            uint32_t t2 = Sigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Add back to state
        a += aa;
        b += bb;
        c += cc;
        d += dd;
        e += ee;
        f += ff;
        g += gg;
        h += hh;
    }

    // Update state
    self->h[0] = a;
    self->h[1] = b;
    self->h[2] = c;
    self->h[3] = d;
    self->h[4] = e;
    self->h[5] = f;
    self->h[6] = g;
    self->h[7] = h;
}

#define min(x, y) ((x) > (y) ? (y) : (x))

// Update SHA256 context with new data
__device__ void sha256_update(Sha256Digest* self, const uint8_t* p, size_t len) {
    self->len += len;

    // Handle any remaining bytes from last update
    if(self->nx > 0) {
        uint32_t n = min(len, SHA256_BLOCK_SIZE - self->nx);
        memcpy(&self->x[self->nx], p, n);
        self->nx += n;

        if(self->nx == SHA256_BLOCK_SIZE) {
            sha256_block_process(self, self->x, 64);
            self->nx = 0;
        }

        p += n;
        len -= n;
    }

    if(len >= SHA256_BLOCK_SIZE) {
        size_t n = len & ~(SHA256_BLOCK_SIZE - 1);
        sha256_block_process(self, p, n);
        p = p + n;
        len -= n;
    }

    if(len != 0) {
        self->nx = len;
        memcpy(self->x, p, self->nx);
    }
}

// Finalize SHA256 calculation and get digest
__device__ void sha256_final(Sha256Digest* self, uint8_t* digest) {
    // Padding buffer
    uint8_t tmp[1 + 63 + 8] = { 0 };
    tmp[0] = 0x80;  // First bit is 1, rest are 0

    // Calculate padding length
    uint64_t pad = (56ULL - self->len) % 64;
    if(pad == 0)
        pad = 64;

    // Add length (in bits)
    be_put_u64(&tmp[pad], self->len << 3);

    // Process padding and length
    sha256_update(self, tmp, pad + 8);

    // Verify nx is 0
    if(self->nx != 0) {
        return;
    }

    // Get final digest
    for(int i = 0; i < 8; i++) {
        be_put_u32(&digest[i * 4], self->h[i]);
    }
}

// Main kernel function to calculate SHA256 for multiple files
__global__ void calculate_sha256_kernel(
    const uint32_t count,
    const uint32_t* file_sizes,
    const uint32_t* file_offsets,
    const uint8_t* data,
    uint8_t* output
) {
    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if(idx >= count) {
        return;
    }

    // Calculate offset for this file's data
    uint64_t offset = file_offsets[idx];

    // Initialize SHA256 context
    Sha256Digest ctx;
    sha256_init(&ctx);

    // Process file data
    sha256_update(&ctx, &data[offset], file_sizes[idx]);

    // Finalize and store result
    sha256_final(&ctx, &output[idx * SHA256_DIGEST_SIZE]);
}

// Helper function to launch the kernel
extern "C" cudaError_t sha256_sum_batch(
    const uint32_t count,
    const uint32_t* file_sizes,
    const uint32_t* file_offsets,
    const uint8_t* data,
    uint8_t* output,
    cudaStream_t stream = 0
) {
    const int threadsPerBlock = 256;
    const int blocksPerGrid = (count + threadsPerBlock - 1) / threadsPerBlock;

    calculate_sha256_kernel<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(
        count, file_sizes, file_offsets, data, output
    );

    return cudaGetLastError();
}
