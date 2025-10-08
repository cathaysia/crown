pub mod aes;
pub mod blowfish;
pub mod camellia;
pub mod cast5;
pub mod des;
pub mod idea;
pub mod rc2;
pub mod rc5;
pub mod rc6;
pub mod skipjack;
pub mod sm4;
pub mod tea;
pub mod twofish;
pub mod xtea;

pub const MAX_BLOCK_SIZE: usize = 144;
/// A Block represents an implementation of block cipher
/// using a given key. It provides the capability to encrypt
/// or decrypt individual blocks. The mode implementations
/// extend that capability to streams of blocks.
pub trait BlockCipher {
    /// BlockSize returns the cipher's block size.
    fn block_size(&self) -> usize;

    /// Encrypt encrypts the first block in src into dst.
    /// Dst and src must overlap entirely or not at all.
    fn encrypt(&self, inout: &mut [u8]);

    /// Decrypt decrypts the first block in src into dst.
    /// Dst and src must overlap entirely or not at all.
    fn decrypt(&self, inout: &mut [u8]);
}

pub trait BlockCipherMarker {}
