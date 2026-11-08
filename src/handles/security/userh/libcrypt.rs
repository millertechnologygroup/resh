//! The system crypt library (libxcrypt or glibc's libcrypt), loaded at run
//! time with `dlopen` so resh neither needs it to build nor fails without
//! it. It verifies every scheme the system's PAM can (yescrypt included).

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::OnceLock;

type CryptR = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> *mut c_char;

/// Room for `struct crypt_data`: 32 KiB in libxcrypt, about 128 KiB in
/// glibc's libcrypt. Allocated as u64 words for alignment.
const DATA_WORDS: usize = 256 * 1024 / 8;

fn crypt_r() -> Option<CryptR> {
    static FN: OnceLock<Option<usize>> = OnceLock::new();
    let addr = *FN.get_or_init(|| {
        for name in [c"libcrypt.so.1", c"libcrypt.so.2", c"libcrypt.so"] {
            // SAFETY: plain C calls with NUL-terminated names; the handle is
            // never closed, so the symbol stays valid.
            unsafe {
                let handle = libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
                if handle.is_null() {
                    continue;
                }
                let sym = libc::dlsym(handle, c"crypt_r".as_ptr());
                if !sym.is_null() {
                    return Some(sym as usize);
                }
            }
        }
        None
    });
    // SAFETY: the address is `crypt_r`, whose C signature is `CryptR`.
    addr.map(|a| unsafe { std::mem::transmute::<usize, CryptR>(a) })
}

/// True when the system crypt library could be loaded.
#[cfg(test)]
pub fn available() -> bool {
    crypt_r().is_some()
}

/// `crypt_r(phrase, setting)`, or `None` when the library is missing or does
/// not support the scheme of `setting` (it then returns `*0`/`*1` or NULL).
pub fn crypt(phrase: &str, setting: &str) -> Option<String> {
    let f = crypt_r()?;
    let phrase = CString::new(phrase).ok()?;
    let setting = CString::new(setting).ok()?;
    // `initialized` (the first field) must be zero.
    let mut data = vec![0u64; DATA_WORDS];
    // SAFETY: both strings are NUL-terminated and `data` is larger and at
    // least as aligned as `struct crypt_data`; the result points into
    // `data`, which outlives its use below.
    let out = unsafe { f(phrase.as_ptr(), setting.as_ptr(), data.as_mut_ptr().cast()) };
    let result = if out.is_null() {
        None
    } else {
        // SAFETY: crypt_r returns a NUL-terminated string.
        unsafe { CStr::from_ptr(out) }
            .to_str()
            .ok()
            .map(str::to_string)
    };
    // The buffer held intermediate values of the hash.
    data.iter_mut().for_each(|w| *w = 0);
    std::hint::black_box(&data);
    result.filter(|r| !r.is_empty() && !r.starts_with('*'))
}

/// Verifies `password` against `hash` with the system library: `None` when
/// it cannot (missing library or unsupported scheme).
pub fn verify(password: &str, hash: &str) -> Option<bool> {
    let computed = crypt(password, hash)?;
    let (a, b) = (computed.as_bytes(), hash.as_bytes());
    Some(a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0)
}
