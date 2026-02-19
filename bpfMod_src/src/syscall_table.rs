//! Syscall name → number lookup table built dynamically from `ausyscall --dump`.
//!
//! Falls back to libseccomp's `ScmpSyscall::from_name()` when ausyscall is
//! unavailable or the name is not found in the table.

use std::collections::HashMap;
use std::process::Command;
use std::sync::OnceLock;

use libseccomp::ScmpSyscall;

/// Global cached syscall table (populated once on first access).
static SYSCALL_TABLE: OnceLock<HashMap<String, i32>> = OnceLock::new();

/// Resolve a syscall name to its number.
///
/// Lookup order:
/// 1. ausyscall table (cached)
/// 2. libseccomp `ScmpSyscall::from_name()`
///
/// Returns `None` if the name cannot be resolved by either source.
pub fn resolve_syscall(name: &str) -> Option<i32> {
    let table = SYSCALL_TABLE.get_or_init(load_ausyscall_table);

    // Primary: ausyscall table
    if let Some(&sysno) = table.get(name) {
        return Some(sysno);
    }

    // Fallback: libseccomp
    ScmpSyscall::from_name(name).ok().map(|s| s.as_raw_syscall())
}

/// Run `ausyscall --dump` and parse the output into a HashMap.
///
/// Output format:
/// ```text
/// Using x86_64 syscall table:
/// 0	read
/// 1	write
/// ...
/// ```
fn load_ausyscall_table() -> HashMap<String, i32> {
    let mut table = HashMap::new();

    let output = match Command::new("ausyscall").arg("--dump").output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            eprintln!(
                "seccomp: ausyscall --dump failed (status={}), using libseccomp only",
                o.status
            );
            return table;
        }
        Err(err) => {
            eprintln!(
                "seccomp: ausyscall not found ({}), using libseccomp only",
                err
            );
            return table;
        }
    };

    let stdout = match std::str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(_) => return table,
    };

    for line in stdout.lines() {
        // Skip header line ("Using x86_64 syscall table:")
        let line = line.trim();
        if line.is_empty() || line.starts_with("Using") {
            continue;
        }

        // Format: "<number>\t<name>"
        let mut parts = line.splitn(2, '\t');
        let num_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let name_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };

        if let Ok(sysno) = num_str.parse::<i32>() {
            table.insert(name_str.to_string(), sysno);
        }
    }

    if !table.is_empty() {
        eprintln!("seccomp: loaded {} syscalls from ausyscall", table.len());
    }

    table
}

/// Get the raw table (for diagnostics / testing).
pub fn get_table() -> &'static HashMap<String, i32> {
    SYSCALL_TABLE.get_or_init(load_ausyscall_table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_table() {
        let table = load_ausyscall_table();
        // ausyscall should be available in the test environment
        if table.is_empty() {
            eprintln!("WARN: ausyscall not available, skipping table content test");
            return;
        }
        // Basic well-known syscalls
        assert_eq!(table.get("read"), Some(&0));
        assert_eq!(table.get("write"), Some(&1));
        assert_eq!(table.get("openat"), Some(&257));
    }

    #[test]
    fn test_resolve_known_syscall() {
        let sysno = resolve_syscall("read");
        assert_eq!(sysno, Some(0));
    }

    #[test]
    fn test_resolve_unknown_syscall() {
        let sysno = resolve_syscall("totally_fake_syscall_xyz");
        assert_eq!(sysno, None);
    }

    #[test]
    fn test_resolve_openat() {
        let sysno = resolve_syscall("openat");
        assert_eq!(sysno, Some(257));
    }
}
