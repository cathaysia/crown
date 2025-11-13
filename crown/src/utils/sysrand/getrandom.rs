#![cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "linux",
    target_os = "solaris"
))]

use nix::errno::Errno;

use super::urandom::urandom_read;
pub fn read(mut b: &mut [u8]) -> std::io::Result<()> {
    // Linux, DragonFly, and illumos don't have a limit on the buffer size.
    // FreeBSD has a limit of IOSIZE_MAX, which seems to be either INT_MAX or
    // SSIZE_MAX. 2^31-1 is a safe and high enough value to use for all of them.
    //
    // Note that Linux returns "a maximum of 32Mi-1 bytes", but that will only
    // result in a short read, not an error. Short reads can also happen above
    // 256 bytes due to signals. Reads up to 256 bytes are guaranteed not to
    // return short (and not to return an error IF THE POOL IS INITIALIZED) on
    // at least Linux, FreeBSD, DragonFly, and Oracle Solaris, but we don't make
    // use of that.
    const MAX_SIZE: usize = if cfg!(target_os = "solaris") {
        // Oracle Solaris has a limit of 133120 bytes. Very specific.
        //
        //    The getrandom() and getentropy() functions fail if: [...]
        //
        //    - bufsz is <= 0 or > 133120, when GRND_RANDOM is not set
        //
        // https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html
        133120
    } else {
        i32::MAX as usize
    };

    while !b.is_empty() {
        let len = b.len().min(MAX_SIZE);
        let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), len as _, 0) };
        if n != -1 {
            b = &mut b[len..];
            continue;
        }

        match Errno::last() {
            Errno::ENOSYS => {
                return urandom_read(b);
            }
            Errno::EINTR => {
                continue;
            }
            errno => return Err(std::io::Error::other(format!("errno: {errno}"))),
        }
    }

    Ok(())
}
