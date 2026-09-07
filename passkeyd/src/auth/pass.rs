use std::ffi::{CStr, CString, c_char};

use log::error;

// libxcrypt is provided as a dependency.
// so, dynamic linking is fine
#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

pub fn verify_password(username: &str, pass: &str) -> anyhow::Result<bool> {
    let username = CString::new(username).unwrap();
    let pass = CString::new(pass).unwrap();

    let spwd_ptr = unsafe { libc::getspnam(username.as_ptr()) };

    if spwd_ptr.is_null() {
        error!("User not found or insufficient privileges");
        anyhow::bail!("User not found or insufficient privileges");
    }

    let hash = unsafe { CStr::from_ptr((*spwd_ptr).sp_pwdp) };

    let result = unsafe { crypt(pass.as_ptr(), hash.as_ptr()) };
    if result.is_null() {
        error!("Crypt failed");
        anyhow::bail!("User not found or insufficient privileges");
    }

    let result = unsafe { CStr::from_ptr(result) };

    return Ok(result == hash);
}
