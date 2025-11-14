#![cfg(all(not(feature = "asm"), not(target_arch = "x86_64")))]

use crate::{
    error::CryptoResult,
    stream::{rc4::Rc4, StreamCipher},
};

impl StreamCipher for Rc4 {
    fn xor_key_stream(&mut self, inout: &mut [u8]) -> CryptoResult<()> {
        if inout.is_empty() {
            return Ok(());
        }

        let mut i = self.i;
        let mut j = self.j;

        for v in inout.iter_mut() {
            i = i.wrapping_add(1);
            let x = self.s[i as usize];
            j = j.wrapping_add(x as u8);
            let y = self.s[j as usize];
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            *v ^= self.s[(x.wrapping_add(y) as u8) as usize] as u8;
        }

        self.i = i;
        self.j = j;
        Ok(())
    }
}
