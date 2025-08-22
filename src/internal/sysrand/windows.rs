#![cfg(target_os = "windows")]

use std::sync::OnceLock;

type BOOL = i32;
type HMODULE = *mut std::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpfilename: *const i8) -> HMODULE;
    fn GetProcAddress(hmodule: HMODULE, lpprocname: *const i8) -> *const std::ffi::c_void;
}

type ProcessPrngFn = unsafe extern "system" fn(pbdata: *mut u8, cbdata: usize) -> BOOL;

static PROCESS_PRNG: OnceLock<Option<ProcessPrngFn>> = OnceLock::new();

fn get_process_prng() -> Option<ProcessPrngFn> {
    *PROCESS_PRNG.get_or_init(|| unsafe {
        let lib_name = b"bcryptprimitives.dll\0";
        let func_name = b"ProcessPrng\0";

        let hmodule = LoadLibraryA(lib_name.as_ptr() as *const i8);
        if hmodule.is_null() {
            return None;
        }

        let proc_addr = GetProcAddress(hmodule, func_name.as_ptr() as *const i8);
        if proc_addr.is_null() {
            return None;
        }

        Some(std::mem::transmute::<*const std::ffi::c_void, ProcessPrngFn>(proc_addr))
    })
}

pub fn read(b: &mut [u8]) -> std::io::Result<()> {
    if let Some(process_prng) = get_process_prng() {
        unsafe {
            process_prng(b.as_mut_ptr().cast(), b.len());
        }
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ProcessPrng function not available",
        ))
    }
}
