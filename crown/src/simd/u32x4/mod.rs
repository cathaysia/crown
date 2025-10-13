use core::{
    arch::x86_64::{
        __m128i, _mm_loadu_si128, _mm_set_epi8, _mm_shuffle_epi8, _mm_storeu_si128, _mm_xor_si128,
    },
    ops::BitXor,
};

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct u32x4(__m128i);

impl u32x4 {
    #[inline(always)]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) })
    }

    #[inline(always)]
    pub fn from_slice(bytes: &[u32]) -> Self {
        Self(unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) })
    }

    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) })
    }

    #[inline(always)]
    pub fn swap_bytes(&self) -> Self {
        unsafe fn m128i_swap_u32_bytes(v: __m128i) -> __m128i {
            let mask = _mm_set_epi8(
                12, 13, 14, 15, // dword3
                8, 9, 10, 11, // dword2
                4, 5, 6, 7, // dword1
                0, 1, 2, 3, // dword0
            );
            _mm_shuffle_epi8(v, mask)
        }

        Self(unsafe { m128i_swap_u32_bytes(self.0) })
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> [u8; 16] {
        let mut v = [0u8; 16];
        unsafe { _mm_storeu_si128(v.as_mut_ptr().cast(), self.0) };
        v
    }

    #[target_feature(enable = "aes")]
    pub unsafe fn aes_enc(self, key: Self) -> Self {
        Self(core::arch::x86_64::_mm_aesenc_si128(self.0, key.0))
    }

    #[target_feature(enable = "aes")]
    pub unsafe fn aes_enc_last(self, key: Self) -> Self {
        Self(core::arch::x86_64::_mm_aesenclast_si128(self.0, key.0))
    }

    #[target_feature(enable = "aes")]
    pub unsafe fn aes_dec(self, key: Self) -> Self {
        Self(core::arch::x86_64::_mm_aesdec_si128(self.0, key.0))
    }

    #[target_feature(enable = "aes")]
    pub unsafe fn aes_dec_last(self, key: Self) -> Self {
        Self(core::arch::x86_64::_mm_aesdeclast_si128(self.0, key.0))
    }
}

impl From<u32x4> for __m128i {
    fn from(value: u32x4) -> Self {
        value.0
    }
}

impl From<__m128i> for u32x4 {
    fn from(value: __m128i) -> Self {
        Self(value)
    }
}

impl BitXor<u32x4> for u32x4 {
    type Output = Self;

    fn bitxor(self, rhs: u32x4) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}
