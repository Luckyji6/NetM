//! Privilege checks.

/// Returns `true` when the process runs with root privileges.
///
/// On Unix this checks `geteuid() == 0`. On Windows it currently always
/// returns `false` (elevation detection lands with the Windows guest port).
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_root_does_not_panic() {
        let _ = super::is_root();
    }
}
