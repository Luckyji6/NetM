//! Privilege checks.

/// Returns `true` when the process runs with root/administrator privileges.
///
/// * Unix: `geteuid() == 0`.
/// * Windows: the process token is elevated (`GetTokenInformation` with
///   `TokenElevation`), i.e. the process was started "as administrator" or
///   UAC is disabled and the user is an administrator.
/// * Anything else: `false`.
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(windows)]
mod windows {
    use std::mem::size_of;
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) fn is_elevated() -> bool {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: plain Win32 calls with valid out-pointers; the token handle
        // is closed before returning.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_root_does_not_panic() {
        let _ = super::is_root();
    }
}
