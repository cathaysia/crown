//! Deterministic xorshift RNG shared by fuzz targets. crown has no ambient
//! entropy source, so targets seed all randomized operations from the fuzz
//! input itself.
#![allow(dead_code)]

/// xorshift64* generator implementing [`crown::rng::Rng`].
pub struct DetRng {
    state: u64,
}

impl DetRng {
    /// Seed the generator. A zero seed is mapped to a nonzero state.
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

impl crown::rng::Rng for DetRng {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Pad or truncate `v` to exactly an `N`-byte array (zero padded).
pub fn fixed<const N: usize>(v: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = v.len().min(N);
    out[..n].copy_from_slice(&v[..n]);
    out
}
