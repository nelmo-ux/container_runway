use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{Action, Error, Policy, PolicyBuilder, Result};
use crate::syscall_table::resolve_syscall;

#[derive(Debug)]
pub struct OciSeccompPolicy {
    pub policy: Policy,
    pub tsync: bool,
    pub notify_sock: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct OciSeccomp {
    #[serde(rename = "defaultAction")]
    default_action: Option<String>,
    #[serde(rename = "architectures", default)]
    architectures: Option<Vec<String>>,
    #[serde(rename = "archMap", default)]
    arch_map: Option<Vec<ArchMapEntry>>,
    #[serde(rename = "syscalls", default)]
    syscalls: Option<Vec<OciSyscall>>,
    #[serde(rename = "errnoRet")]
    errno_ret: Option<i64>,
    /// Docker uses `defaultErrnoRet` instead of `errnoRet`.
    #[serde(rename = "defaultErrnoRet")]
    default_errno_ret: Option<i64>,
    #[serde(rename = "flags", default)]
    flags: Option<Vec<String>>,
    #[serde(rename = "listenerPath")]
    listener_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct ArchMapEntry {
    architecture: String,
    #[serde(rename = "subArchitectures", default)]
    #[allow(dead_code)]
    sub_architectures: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OciSyscall {
    names: Vec<String>,
    action: String,
    #[serde(rename = "errnoRet")]
    errno_ret: Option<i64>,
    #[serde(default)]
    args: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    includes: Option<serde_json::Value>,
    #[serde(default)]
    excludes: Option<serde_json::Value>,
}

/// Check if `args` contains non-empty entries.
fn has_effective_args(args: &Option<Vec<serde_json::Value>>) -> bool {
    match args {
        Some(v) => !v.is_empty(),
        None => false,
    }
}

/// Check if `includes`/`excludes` contains non-empty entries.
#[cfg(test)]
fn has_effective_filter(filter: &Option<serde_json::Value>) -> bool {
    match filter {
        Some(serde_json::Value::Object(map)) => !map.is_empty(),
        Some(serde_json::Value::Null) => false,
        Some(_) => true,
        None => false,
    }
}

/// Docker arch aliases that map to x86_64.
const X86_64_ALIASES: &[&str] = &[
    "amd64", "x86_64", "x86", "x32",
    "SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32",
];

/// Check if an `arches` list includes an x86_64-compatible architecture.
fn arches_match_x86_64(arches: &[serde_json::Value]) -> bool {
    arches.iter().any(|v| {
        if let Some(s) = v.as_str() {
            X86_64_ALIASES.iter().any(|alias| alias.eq_ignore_ascii_case(s))
        } else {
            false
        }
    })
}

/// Evaluate whether a syscall entry should be included based on Docker-style
/// `includes`/`excludes` conditions.
///
/// Returns `ShouldApply::Yes` if the rule should be applied,
/// `ShouldApply::No` if it should be skipped,
/// `ShouldApply::Unsupported` if conditions cannot be evaluated.
enum ShouldApply {
    Yes,
    No,
    Unsupported,
}

/// Evaluate `includes` condition. The rule applies only if ALL conditions match.
/// We can evaluate `arches`; `caps` and `minKernel` are unsupported.
fn eval_includes(includes: &Option<serde_json::Value>) -> ShouldApply {
    let Some(serde_json::Value::Object(map)) = includes else {
        return ShouldApply::Yes; // no condition = always include
    };
    if map.is_empty() {
        return ShouldApply::Yes;
    }

    // If there are conditions we can't evaluate (caps, minKernel), skip.
    let has_caps = map.contains_key("caps");
    let has_min_kernel = map.contains_key("minKernel");
    let has_arches = map.contains_key("arches");

    if has_caps || has_min_kernel {
        // Has unevaluable conditions. Even if arches also present,
        // all conditions must match, so we can't determine the result.
        return ShouldApply::Unsupported;
    }

    if has_arches {
        if let Some(serde_json::Value::Array(arches)) = map.get("arches") {
            if arches_match_x86_64(arches) {
                return ShouldApply::Yes;
            } else {
                return ShouldApply::No; // arches don't include x86_64, skip
            }
        }
    }

    // Unknown condition keys
    ShouldApply::Unsupported
}

/// Evaluate `excludes` condition. The rule is excluded if ANY condition matches.
fn eval_excludes(excludes: &Option<serde_json::Value>) -> ShouldApply {
    let Some(serde_json::Value::Object(map)) = excludes else {
        return ShouldApply::Yes; // no condition = don't exclude
    };
    if map.is_empty() {
        return ShouldApply::Yes;
    }

    let has_caps = map.contains_key("caps");
    let has_arches = map.contains_key("arches");

    // If only arches condition and it matches -> exclude this rule
    if has_arches {
        if let Some(serde_json::Value::Array(arches)) = map.get("arches") {
            if arches_match_x86_64(arches) {
                return ShouldApply::No; // excluded for our arch
            }
            // arches don't match x86_64, so this exclude doesn't apply
            if !has_caps {
                return ShouldApply::Yes;
            }
        }
    }

    if has_caps {
        // Can't evaluate caps; skip to be safe (don't apply uncertain rules)
        return ShouldApply::Unsupported;
    }

    ShouldApply::Unsupported
}

/// Extract architecture strings from Docker's `archMap` format.
///
/// Docker format:
/// ```json
/// "archMap": [
///   { "architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"] }
/// ]
/// ```
///
/// Returns a flat list of primary architecture names (subArchitectures are ignored
/// since they are only relevant for multilib compat filtering which we don't support).
fn extract_architectures_from_arch_map(arch_map: &[ArchMapEntry]) -> Vec<String> {
    arch_map.iter().map(|entry| entry.architecture.clone()).collect()
}

/// Resolve the effective architecture list from either `architectures` or `archMap`.
fn resolve_architectures(seccomp: &OciSeccomp) -> Option<Vec<String>> {
    if let Some(ref archs) = seccomp.architectures {
        if !archs.is_empty() {
            return Some(archs.clone());
        }
    }
    if let Some(ref arch_map) = seccomp.arch_map {
        if !arch_map.is_empty() {
            return Some(extract_architectures_from_arch_map(arch_map));
        }
    }
    None
}

pub fn load_oci_seccomp_policy(path: &Path) -> Result<OciSeccompPolicy> {
    let data = std::fs::read_to_string(path)?;
    let seccomp = parse_seccomp_json(&data)?;
    build_seccomp_policy(seccomp)
}

/// Parse seccomp JSON, auto-detecting OCI format (`linux.seccomp` wrapper)
/// or Docker format (flat top-level with `defaultAction`).
fn parse_seccomp_json(data: &str) -> Result<OciSeccomp> {
    // First, try OCI format: { "linux": { "seccomp": { ... } } }
    let raw: serde_json::Value = serde_json::from_str(data)
        .map_err(|err| Error::OciSeccomp(format!("invalid json: {err}")))?;

    if let Some(linux) = raw.get("linux").and_then(|l| l.get("seccomp")) {
        let seccomp: OciSeccomp = serde_json::from_value(linux.clone())
            .map_err(|err| Error::OciSeccomp(format!("invalid linux.seccomp: {err}")))?;
        return Ok(seccomp);
    }

    // Fallback: Docker format (flat top-level with defaultAction)
    if raw.get("defaultAction").is_some() {
        let seccomp: OciSeccomp = serde_json::from_value(raw)
            .map_err(|err| Error::OciSeccomp(format!("invalid docker seccomp profile: {err}")))?;
        return Ok(seccomp);
    }

    Err(Error::OciSeccomp(
        "seccomp config must be OCI format (linux.seccomp) or Docker format (top-level defaultAction)".to_string(),
    ))
}

fn build_seccomp_policy(seccomp: OciSeccomp) -> Result<OciSeccompPolicy> {
    let architectures = resolve_architectures(&seccomp);
    validate_architectures(&architectures)?;

    let default_action_name = seccomp
        .default_action
        .ok_or_else(|| Error::OciSeccomp("defaultAction is missing".to_string()))?;
    // Docker uses `defaultErrnoRet`, OCI uses `errnoRet`.
    let errno_source = seccomp.errno_ret.or(seccomp.default_errno_ret);
    let default_errno = parse_errno(errno_source)?;
    let default_action = parse_action(&default_action_name, None, default_errno)?;

    let mut builder = PolicyBuilder::new(default_action);
    let mut skipped: usize = 0;

    if let Some(syscalls) = seccomp.syscalls {
        for entry in syscalls {
            // Skip rules with argument-level filtering (not supported).
            if has_effective_args(&entry.args) {
                skipped += 1;
                continue;
            }

            // Evaluate includes condition (arches-only can be resolved).
            match eval_includes(&entry.includes) {
                ShouldApply::No => continue,        // arches don't match, skip
                ShouldApply::Unsupported => {        // caps/minKernel, can't evaluate
                    skipped += 1;
                    continue;
                }
                ShouldApply::Yes => {}
            }

            // Evaluate excludes condition.
            match eval_excludes(&entry.excludes) {
                ShouldApply::No => continue,        // excluded for our arch
                ShouldApply::Unsupported => {        // caps, can't evaluate
                    skipped += 1;
                    continue;
                }
                ShouldApply::Yes => {}
            }

            if entry.names.is_empty() {
                continue;
            }

            let action = parse_action(&entry.action, entry.errno_ret, default_errno)?;
            for name in &entry.names {
                match resolve_syscall(name) {
                    Some(sysno) => {
                        builder.rule(sysno, action);
                    }
                    None => {
                        // Skip unknown syscalls (e.g. arch-specific names like arm_fadvise64_64).
                        continue;
                    }
                }
            }
        }
    }

    if skipped > 0 {
        eprintln!(
            "seccomp: skipped {} rule(s) with unsupported args/includes/excludes conditions",
            skipped
        );
    }

    let tsync = seccomp
        .flags
        .as_ref()
        .map(|flags| {
            flags.iter().any(|flag| {
                flag.eq_ignore_ascii_case("SECCOMP_FILTER_FLAG_TSYNC")
            })
        })
        .unwrap_or(false);

    Ok(OciSeccompPolicy {
        policy: builder.build(),
        tsync,
        notify_sock: seccomp.listener_path,
    })
}

fn parse_errno(value: Option<i64>) -> Result<u16> {
    let errno = value.unwrap_or(1);
    if errno <= 0 || errno > u16::MAX as i64 {
        return Err(Error::OciSeccomp(format!(
            "invalid errnoRet value: {errno}"
        )));
    }
    Ok(errno as u16)
}

fn parse_action(name: &str, errno_ret: Option<i64>, default_errno: u16) -> Result<Action> {
    let normalized = name.trim().to_uppercase();
    match normalized.as_str() {
        "SCMP_ACT_ALLOW" | "ALLOW" => Ok(Action::Allow),
        "SCMP_ACT_ERRNO" | "ERRNO" => {
            let errno = match errno_ret {
                Some(value) => parse_errno(Some(value))?,
                None => default_errno,
            };
            Ok(Action::Errno(errno))
        }
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_PROCESS" | "SCMP_ACT_KILL_THREAD" | "KILL" => {
            Ok(Action::KillProcess)
        }
        "SCMP_ACT_LOG" | "LOG" => Ok(Action::Log),
        "SCMP_ACT_NOTIFY" | "NOTIFY" => Ok(Action::UserNotif),
        "SCMP_ACT_TRAP" | "TRAP" => Err(Error::OciSeccomp(
            "SCMP_ACT_TRAP is not supported".to_string(),
        )),
        "SCMP_ACT_TRACE" | "TRACE" => Err(Error::OciSeccomp(
            "SCMP_ACT_TRACE is not supported".to_string(),
        )),
        _ => Err(Error::OciSeccomp(format!(
            "unsupported seccomp action: {name}"
        ))),
    }
}

fn validate_architectures(architectures: &Option<Vec<String>>) -> Result<()> {
    let Some(archs) = architectures else {
        return Ok(());
    };
    if archs.is_empty() {
        return Ok(());
    }
    let mut supported = false;
    for arch in archs {
        let upper = arch.trim().to_uppercase();
        if upper == "SCMP_ARCH_X86_64"
            || upper == "SCMP_ARCH_NATIVE"
            || upper == "X86_64"
            || upper == "AMD64"
            || upper == "NATIVE"
        {
            supported = true;
            break;
        }
    }
    if !supported {
        return Err(Error::OciSeccomp(
            "seccomp.architectures does not include SCMP_ARCH_X86_64/NATIVE".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_format_flat() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["read", "write"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [],
                    "includes": {},
                    "excludes": {}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        assert_eq!(seccomp.default_action.as_deref(), Some("SCMP_ACT_ERRNO"));
        assert!(seccomp.syscalls.is_some());
    }

    #[test]
    fn test_oci_format_nested() {
        let json = r#"{
            "linux": {
                "seccomp": {
                    "defaultAction": "SCMP_ACT_ALLOW",
                    "syscalls": [
                        {
                            "names": ["openat"],
                            "action": "SCMP_ACT_ERRNO",
                            "errnoRet": 1
                        }
                    ]
                }
            }
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        assert_eq!(seccomp.default_action.as_deref(), Some("SCMP_ACT_ALLOW"));
    }

    #[test]
    fn test_docker_arch_map() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "archMap": [
                {
                    "architecture": "SCMP_ARCH_X86_64",
                    "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]
                }
            ],
            "syscalls": []
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let archs = resolve_architectures(&seccomp);
        assert_eq!(archs, Some(vec!["SCMP_ARCH_X86_64".to_string()]));
    }

    #[test]
    fn test_empty_args_ignored() {
        assert!(!has_effective_args(&None));
        assert!(!has_effective_args(&Some(vec![])));
        assert!(has_effective_args(&Some(vec![serde_json::Value::Null])));
    }

    #[test]
    fn test_empty_filter_ignored() {
        assert!(!has_effective_filter(&None));
        assert!(!has_effective_filter(&Some(serde_json::Value::Object(
            serde_json::Map::new()
        ))));
        assert!(!has_effective_filter(&Some(serde_json::Value::Null)));
        assert!(has_effective_filter(&Some(serde_json::json!({"caps": ["CAP_SYS_ADMIN"]}))));
    }

    #[test]
    fn test_docker_full_profile() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "archMap": [
                {
                    "architecture": "SCMP_ARCH_X86_64",
                    "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]
                }
            ],
            "syscalls": [
                {
                    "names": ["read", "write", "exit", "exit_group"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [],
                    "comment": "basic I/O",
                    "includes": {},
                    "excludes": {}
                },
                {
                    "names": ["clone"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [],
                    "includes": {},
                    "excludes": {}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp);
        assert!(result.is_ok());
        let policy = result.unwrap();
        assert!(!policy.tsync);
        assert!(policy.notify_sock.is_none());
    }

    #[test]
    fn test_non_empty_args_skipped() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["read", "write"],
                    "action": "SCMP_ACT_ALLOW"
                },
                {
                    "names": ["socket"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": 2, "op": "SCMP_CMP_EQ"}]
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp);
        assert!(result.is_ok());
        // "socket" rule with args should be skipped; only read+write applied
        let policy = result.unwrap();
        assert_eq!(policy.policy.rules.len(), 2);
    }

    #[test]
    fn test_default_errno_ret() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 42,
            "syscalls": []
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp).unwrap();
        assert!(matches!(result.policy.default_action, Action::Errno(42)));
    }

    #[test]
    fn test_includes_arches_match() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["arch_prctl"],
                    "action": "SCMP_ACT_ALLOW",
                    "includes": {"arches": ["amd64", "x32"]}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp).unwrap();
        // arch_prctl should be applied (amd64 matches x86_64)
        assert_eq!(result.policy.rules.len(), 1);
    }

    #[test]
    fn test_includes_arches_no_match() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["arm_fadvise64_64"],
                    "action": "SCMP_ACT_ALLOW",
                    "includes": {"arches": ["arm", "arm64"]}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp).unwrap();
        // arm-only rule should be skipped
        assert_eq!(result.policy.rules.len(), 0);
    }

    #[test]
    fn test_includes_caps_skipped() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["bpf"],
                    "action": "SCMP_ACT_ALLOW",
                    "includes": {"caps": ["CAP_SYS_ADMIN"]}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp).unwrap();
        // caps-based includes can't be evaluated, skip
        assert_eq!(result.policy.rules.len(), 0);
    }

    #[test]
    fn test_excludes_arches_match() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["read"],
                    "action": "SCMP_ACT_ALLOW",
                    "excludes": {"arches": ["amd64"]}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp).unwrap();
        // excluded for amd64
        assert_eq!(result.policy.rules.len(), 0);
    }

    #[test]
    fn test_excludes_arches_no_match() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ERRNO",
            "syscalls": [
                {
                    "names": ["read"],
                    "action": "SCMP_ACT_ALLOW",
                    "excludes": {"arches": ["s390", "s390x"]}
                }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let result = build_seccomp_policy(seccomp).unwrap();
        // not excluded (arches don't match x86_64)
        assert_eq!(result.policy.rules.len(), 1);
    }

    #[test]
    fn test_invalid_format_rejected() {
        let json = r#"{"foo": "bar"}"#;
        let result = parse_seccomp_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_architectures_takes_precedence_over_arch_map() {
        let json = r#"{
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64"],
            "archMap": [
                { "architecture": "SCMP_ARCH_AARCH64", "subArchitectures": [] }
            ]
        }"#;
        let seccomp = parse_seccomp_json(json).unwrap();
        let archs = resolve_architectures(&seccomp);
        assert_eq!(archs, Some(vec!["SCMP_ARCH_X86_64".to_string()]));
    }
}
