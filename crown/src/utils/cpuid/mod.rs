#[repr(C)]
pub struct CpuId {
    /// cap[0]: CPUID(EAX=1).EDX - (MMX, SSE, SSE2)
    pub cap0: u32,
    /// cap[1]: CPUID(EAX=1).ECX - (AES-NI, PCLMULQDQ, AVX)
    pub cap1: u32,
    /// cap[2]: CPUID(EAX=7,ECX=0).EBX - AVX2 and new instructions
    pub cap2: u32,
    /// cap[3]: OpenSSL internal
    pub cap3: u32,
}

pub fn cpuid() -> CpuId {
    let mut cap0 = 0u32;
    let mut cap1 = 0u32;
    let mut cap2 = 0u32;
    let mut cap3 = 0u32;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("mmx") {
            cap0 |= 1 << 23; // bit 23: MMX
        }
        if is_x86_feature_detected!("sse") {
            cap0 |= 1 << 25; // bit 25: SSE
        }
        if is_x86_feature_detected!("sse2") {
            cap0 |= 1 << 26; // bit 26: SSE2
        }

        if is_x86_feature_detected!("pclmulqdq") {
            cap1 |= 1 << 1; // bit 1: PCLMULQDQ
        }
        if is_x86_feature_detected!("fma") {
            cap1 |= 1 << 12; // bit 12: FMA
        }
        if is_x86_feature_detected!("sse4.1") {
            cap1 |= 1 << 19; // bit 19: SSE4.1
        }
        if is_x86_feature_detected!("sse4.2") {
            cap1 |= 1 << 20; // bit 20: SSE4.2
        }
        if is_x86_feature_detected!("aes") {
            cap1 |= 1 << 25; // bit 25: AES-NI
        }
        // bit 27: OSXSAVE -
        if is_x86_feature_detected!("avx") {
            cap1 |= 1 << 27; // bit 27: OSXSAVE
            cap1 |= 1 << 28; // bit 28: AVX
        }

        // cap[2]: CPUID(7,0).EBX
        if is_x86_feature_detected!("avx2") {
            cap2 |= 1 << 5; // bit 5: AVX2
        }
        if is_x86_feature_detected!("bmi2") {
            cap2 |= 1 << 8; // bit 8: BMI2
        }
        if cfg!(target_feature = "adx") || is_x86_feature_detected!("adx") {
            cap2 |= 1 << 19; // bit 19: ADX
        }
        if is_x86_feature_detected!("sha") {
            cap2 |= 1 << 29; // bit 29: SHA-NI
        }

        if is_x86_feature_detected!("avx") {
            cap3 |= 1 << 0; // bit 0: AVX usable
        }
        if is_x86_feature_detected!("avx2") {
            cap3 |= 1 << 6; // bit 6: AVX2 usable
        }
        if is_x86_feature_detected!("bmi2") {
            cap3 |= 1 << 7; // bit 7: BMI2 usable
        }
    }

    CpuId {
        cap0,
        cap1,
        cap2,
        cap3,
    }
}
