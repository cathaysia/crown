#![cfg(all(feature = "asm", target_arch = "x86_64"))]

use crate::{
    error::CryptoResult,
    stream::{rc4::Rc4, StreamCipher},
};

core::arch::global_asm!(
    crown_derive::jsasm_file!("crown/src/stream/rc4/xor_key_stream/x86_64.ts"),
    options(att_syntax)
);

/// OpenSSL RC4 state layout
/// Memory layout expected by OpenSSL RC4 assembly:
/// [i:u8][pad:3][j:u8][pad:3][s:u32×256][char_mode:i32]
///  ↑ dat-8      ↑ dat-4     ↑ dat (pointer passed to RC4 function)
#[repr(C, align(8))]
struct Rc4State {
    i: u8,
    _pad1: [u8; 3],
    j: u8,
    _pad2: [u8; 3],
    s: [u32; 256],
    char_mode: i32,
}

impl Rc4State {
    /// Create OpenSSL-compatible state from Rust Rc4
    fn from_rc4(rc4: &Rc4) -> Self {
        let mut state = Self {
            i: rc4.i,
            _pad1: [0; 3],
            j: rc4.j,
            _pad2: [0; 3],
            s: [0; 256],
            char_mode: -1, // Use INT mode (not CHAR mode)
        };
        state.s.copy_from_slice(&rc4.s);
        state
    }

    /// Copy state back to Rust Rc4
    fn copy_to_rc4(&self, rc4: &mut Rc4) {
        rc4.i = self.i;
        rc4.j = self.j;
        // Note: rc4.s is already modified in-place, but we ensure consistency
        rc4.s.copy_from_slice(&self.s);
    }

    /// Get pointer to s array (dat parameter for RC4 function)
    fn dat_ptr(&mut self) -> *mut u8 {
        self.s.as_mut_ptr() as *mut u8
    }
}

extern "C" {
    /// RC4 encryption/decryption function
    ///
    /// Parameters:
    /// - dat: Pointer to s[0] in Rc4State (i is at dat-8, j is at dat-4)
    /// - len: Length of data to process
    /// - inp: Input data pointer
    /// - out: Output data pointer
    fn RC4(dat: *mut u8, len: usize, inp: *const u8, out: *mut u8);
}

impl StreamCipher for Rc4 {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        if inout.is_empty() {
            return Ok(());
        }

        // Create OpenSSL-compatible state
        let mut state = Rc4State::from_rc4(self);

        // Call assembly function (in-place encryption)
        unsafe {
            RC4(
                state.dat_ptr(),
                inout.len(),
                inout.as_ptr(),
                inout.as_mut_ptr(),
            );
        }

        // Copy state back
        state.copy_to_rc4(self);

        Ok(())
    }
}
