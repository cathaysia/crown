use super::*;
use kittycrypto::core::{CoreRead, CoreWrite};
use kittycrypto::envelope::EvpHash;
use kittycrypto::hash::HashUser;

pub struct Hash(EvpHash);

macro_rules! impl_hash_methods {
    (
        normal: [$($normal:ident),* $(,)?],
        variant: [$($variant:ident),* $(,)?] $(,)?
    ) => {
        $(
            paste::paste! {
                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<hash_new_ $normal:lower>]() -> *mut Self {
                    match EvpHash::[<new_ $normal:lower>]() {
                        Ok(hash) => Box::into_raw(Box::new(Self(hash))),
                        Err(_) => std::ptr::null_mut(),
                    }
                }

                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<hash_new_ $normal:lower _hmac>](
                    key: *const u8,
                    key_len: usize
                ) -> *mut Self {
                    unsafe {
                        let key_slice = match slice_from_raw_parts(key, key_len) {
                            Some(slice) => slice,
                            None => return std::ptr::null_mut(),
                        };

                        match EvpHash::[<new_ $normal:lower _hmac>](key_slice) {
                            Ok(hash) => Box::into_raw(Box::new(Self(hash))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }
            }
        )*
        $(
            paste::paste! {
                #[unsafe(no_mangle)]
                pub unsafe extern "C" fn [<hash_new_ $variant:lower>](
                    key: *const u8,
                    key_len: usize,
                    output_len: usize
                ) -> *mut Self {
                    unsafe {
                        let key_opt = if key.is_null() {
                            None
                        } else {
                            slice_from_raw_parts(key, key_len)
                        };

                        match EvpHash::[<new_ $variant:lower>](key_opt, output_len) {
                            Ok(hash) => Box::into_raw(Box::new(Self(hash))),
                            Err(_) => std::ptr::null_mut(),
                        }
                    }
                }
            }
        )*
    };
}

impl Hash {
    impl_hash_methods!(
        normal: [
            md2, md4, md5, sha1, sha224, sha256, sha384, sha512,
            sha512_224, sha512_256, sha3_224, sha3_256, sha3_384,
            sha3_512, shake128, shake256, sm3
        ],
        variant: [blake2s, blake2b],
    );

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn hash_write(&mut self, data: *const u8, len: usize) -> i32 {
        if data.is_null() || len == 0 {
            return 0;
        }

        let data_slice = unsafe { std::slice::from_raw_parts(data, len) };
        match self.0.write(data_slice) {
            Ok(written) => written as i32,
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn hash_flush(&mut self) -> i32 {
        match self.0.flush() {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn hash_read(&mut self, buf: *mut u8, len: usize) -> i32 {
        if buf.is_null() || len == 0 {
            return 0;
        }

        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        match self.0.read(buf_slice) {
            Ok(read) => read as i32,
            Err(_) => -1,
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn hash_sum(&mut self, output: *mut u8, output_len: usize) -> i32 {
        if output.is_null() {
            return -1;
        }

        let result = self.0.sum();
        if output_len < result.len() {
            return -1;
        }

        let output_slice = unsafe { std::slice::from_raw_parts_mut(output, output_len) };
        output_slice[..result.len()].copy_from_slice(&result);
        result.len() as i32
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn hash_reset(&mut self) {
        self.0.reset();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn hash_size(&self) -> usize {
        self.0.size()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn hash_block_size(&self) -> usize {
        self.0.block_size()
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn hash_free(hash: *mut Self) {
        if !hash.is_null() {
            unsafe {
                let _ = Box::from_raw(hash);
            }
        }
    }
}
