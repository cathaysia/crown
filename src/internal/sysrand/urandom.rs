#![allow(dead_code)]
// The urandom fallback is only used on Linux kernels before 3.17 and on AIX.

use std::{fs::File, io::Read, sync::Once};

static URANDOM_ONCE: Once = Once::new();
static mut URANDOM_FILE: Option<File> = None;
static mut URANDOM_ERR: Option<std::io::Error> = None;
pub(crate) fn urandom_read(b: &mut [u8]) -> std::io::Result<()> {
    unsafe {
        URANDOM_ONCE.call_once(|| match File::open("/dev/urandom") {
            Ok(file) => URANDOM_FILE = Some(file),
            Err(err) => URANDOM_ERR = Some(err),
        });

        if let Some(ref err) = URANDOM_ERR {
            return Err(std::io::Error::new(err.kind(), format!("{}", err)));
        }

        if let Some(ref mut file) = URANDOM_FILE {
            let mut remaining = b;
            while !remaining.is_empty() {
                match file.read(remaining) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected EOF reading /dev/urandom",
                        ))
                    }
                    Ok(n) => {
                        // Note that we don't ignore EAGAIN because it should not be possible to
                        // hit for a blocking read from urandom, although there were
                        // unreproducible reports of it at https://go.dev/issue/9205.
                        remaining = &mut remaining[n..];
                    }
                    Err(err) => return Err(err),
                }
            }
        }
    }
    Ok(())
}
