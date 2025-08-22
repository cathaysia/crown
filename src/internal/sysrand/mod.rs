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

static mut TESTING_ONLY_FAIL_READ: bool = false;

// Read fills b with cryptographically secure random bytes from the operating
// system. It always fills b entirely and crashes the program irrecoverably if
// an error is encountered. The operating system APIs are documented to never
// return an error on all but legacy Linux systems.
pub fn fill_bytes(b: &mut [u8]) {
    unsafe {
        if read(b).is_err() || TESTING_ONLY_FAIL_READ {
            let err_str = if !TESTING_ONLY_FAIL_READ {
                "system random read failed"
            } else {
                "testing simulated failure"
            };
            panic!(
                "crypto/rand: failed to read random data (see https://go.dev/issue/66821): {}",
                err_str
            );
        }
    }
}
