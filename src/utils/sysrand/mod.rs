mod arc4random;
#[cfg(any(target_os = "macos", target_os = "openbsd"))]
use arc4random::*;

mod getrandom;
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "solaris"
))]
use getrandom::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;

mod urandom;

/// Read fills b with cryptographically secure random bytes from the operating
/// system. It always fills b entirely and crashes the program irrecoverably if
/// an error is encountered. The operating system APIs are documented to never
/// return an error on all but legacy Linux systems.
pub fn fill_bytes(b: &mut [u8]) {
    if read(b).is_err() {
        panic!("failed to read random data: system random read failed");
    }
}
