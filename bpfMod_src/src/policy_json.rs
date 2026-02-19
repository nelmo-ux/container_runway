use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub default: Option<PolicyDefault>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyDefault {
    pub action: PolicyAction,
    #[serde(default)]
    pub errno: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub sysno: i32,
    pub action: PolicyAction,
    #[serde(default)]
    pub errno: Option<i32>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyAction {
    Allow,
    Deny,
    Errno,
}

pub fn load_policy(path: &Path) -> Result<PolicyFile, PolicyLoadError> {
    let data = std::fs::read_to_string(path)?;
    let policy = serde_json::from_str::<PolicyFile>(&data)?;
    Ok(policy)
}
