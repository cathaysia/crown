// Declare assembly functions using OpenSSL calling convention
extern "C" {
    // Initialize function: poly1305_init(ctx, key, func_ptrs) -> int
    // ctx: pointer to state structure (needs at least 48 bytes)
    // key: 32-byte key, if null only zeros the state
    // func_ptrs: output function pointer array [blocks_func, emit_func]
    fn poly1305_init(
        ctx: *mut u8,          // state buffer
        key: *const u8,        // 32-byte key
        func_ptrs: *mut usize, // function pointer array
    ) -> i32;

    // Process data blocks: poly1305_blocks(ctx, inp, len, padbit)
    // ctx: state pointer
    // inp: input data
    // len: data length (must be multiple of 16)
    // padbit: padding bit (usually 1)
    fn poly1305_blocks(ctx: *mut u8, inp: *const u8, len: usize, padbit: u32);

    // Generate MAC: poly1305_emit(ctx, mac, nonce)
    // ctx: state pointer
    // mac: output 16-byte MAC
    // nonce: 16-byte nonce
    fn poly1305_emit(ctx: *mut u8, mac: *mut u8, nonce: *const u8);
}

/// AArch64 optimized Poly1305 MAC state
/// Memory layout must be compatible with OpenSSL assembly code
#[repr(C)]
pub struct MacAarch64 {
    // OpenSSL poly1305 state structure:
    // [0..24]: hash value (h0, h1, h2) - 3 u64 values
    // [24..40]: key (r0, r1) - 2 u64 values
    // [40..48]: is_base2_26 flag and padding
    // [48..]: function pointers and other data
    state: [u8; 256], // Large enough buffer for OpenSSL state
    buffer: [u8; 16], // Buffer for incomplete blocks
    offset: usize,    // Current buffer offset
    nonce: [u8; 16],  // Store nonce separately
}

impl MacAarch64 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut mac = MacAarch64 {
            state: [0u8; 256],
            buffer: [0u8; 16],
            offset: 0,
            nonce: [0u8; 16],
        };

        // Store nonce part of key
        mac.nonce.copy_from_slice(&key[16..32]);

        // Initialize state with assembly function
        let mut func_ptrs: [usize; 2] = [0; 2];
        unsafe {
            poly1305_init(mac.state.as_mut_ptr(), key.as_ptr(), func_ptrs.as_mut_ptr());
        }

        mac
    }

    pub fn write(&mut self, mut data: &[u8]) -> usize {
        let original_len = data.len();

        // Handle buffered data first
        if self.offset > 0 {
            let need = 16 - self.offset;
            let take = data.len().min(need);
            self.buffer[self.offset..self.offset + take].copy_from_slice(&data[..take]);
            self.offset += take;
            data = &data[take..];

            if self.offset == 16 {
                unsafe {
                    poly1305_blocks(
                        self.state.as_mut_ptr(),
                        self.buffer.as_ptr(),
                        16,
                        1, // padbit = 1 for normal blocks
                    );
                }
                self.offset = 0;
            }
        }

        // Process complete 16-byte blocks
        if data.len() >= 16 {
            let blocks_len = data.len() & !15; // Round down to multiple of 16
            unsafe {
                poly1305_blocks(
                    self.state.as_mut_ptr(),
                    data.as_ptr(),
                    blocks_len,
                    1, // padbit = 1 for normal blocks
                );
            }
            data = &data[blocks_len..];
        }

        // Buffer remaining data
        if !data.is_empty() {
            self.buffer[self.offset..self.offset + data.len()].copy_from_slice(data);
            self.offset += data.len();
        }

        original_len
    }

    pub fn sum(&self) -> [u8; 16] {
        // Copy state for final processing
        let mut temp_state = self.state;

        // Process final incomplete block if any
        if self.offset > 0 {
            let mut final_block = [0u8; 16];
            final_block[..self.offset].copy_from_slice(&self.buffer[..self.offset]);
            final_block[self.offset] = 1; // Add padding bit

            unsafe {
                poly1305_blocks(
                    temp_state.as_mut_ptr(),
                    final_block.as_ptr(),
                    16, // Always process 16 bytes for final block
                    0,  // padbit = 0 for final block
                );
            }
        }

        let mut out = [0u8; 16];
        // Generate MAC using assembly function
        unsafe {
            poly1305_emit(
                temp_state.as_mut_ptr(),
                out.as_mut_ptr(),
                self.nonce.as_ptr(),
            );
        }
        out
    }
}
