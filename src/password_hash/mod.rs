#[cfg(feature = "alloc")]
pub mod argon2;
#[cfg(feature = "std")]
pub mod bcrypt;
#[cfg(feature = "alloc")]
pub mod pbkdf2;
#[cfg(feature = "alloc")]
pub mod scrypt;
