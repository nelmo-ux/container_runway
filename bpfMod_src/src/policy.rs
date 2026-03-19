use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd};

use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use libseccomp::error::SeccompError;
#[cfg(target_arch = "x86_64")]
use libseccomp::ScmpArch;
use nix::Error as NixError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Errno(u16),
    KillProcess,
    Log,
    UserNotif,
}

impl Default for Action {
    fn default() -> Self {
        Action::Allow
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgCmp {
    pub arg: u32,
    pub op: CmpOp,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    NotEqual,
    Less,
    LessOrEqual,
    Equal,
    GreaterEqual,
    Greater,
    MaskedEqual { mask: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub syscall: i32,
    pub action: Action,
    pub args: Vec<ArgCmp>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub default_action: Action,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy)]
pub struct ApplyOptions {
    pub tsync: bool,
    pub no_new_privs: bool,
    pub new_listener: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            tsync: false,
            no_new_privs: true,
            new_listener: false,
        }
    }
}

#[derive(Debug)]
pub struct AppliedFilter {
    pub listener_fd: Option<OwnedFd>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid syscall number: {0}")]
    InvalidSyscall(String),
    #[error("invalid errno: {0}")]
    InvalidErrno(u16),
    #[error("notify socket is required when using user-notif actions")]
    NotifySockRequired,
    #[error("notify listener fd missing")]
    NotifyListenerMissing,
    #[error("pid mismatch: expected {expected}, got {actual}")]
    PidMismatch { expected: u32, actual: u32 },
    #[error("rule parse error: {0}")]
    ParseRule(String),
    #[error("exec failed: {0}")]
    ExecFailed(String),
    #[error("policy load error: {0}")]
    PolicyLoad(String),
    #[error("oci seccomp error: {0}")]
    OciSeccomp(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix error: {0}")]
    Nix(#[from] NixError),
    #[error("seccomp error: {0}")]
    Seccomp(#[from] SeccompError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Priority {
    Allow = 0,
    Deny = 1,
    Rule = 2,
}

#[derive(Debug, Clone, Copy)]
struct PendingRule {
    action: Action,
    priority: Priority,
}

#[derive(Debug, Default)]
pub struct PolicyBuilder {
    default_action: Action,
    rules: HashMap<i32, PendingRule>,
    conditional_rules: Vec<Rule>,
}

impl PolicyBuilder {
    pub fn new(default_action: Action) -> Self {
        Self {
            default_action,
            rules: HashMap::new(),
            conditional_rules: Vec::new(),
        }
    }

    pub fn default_action(&mut self, action: Action) -> &mut Self {
        self.default_action = action;
        self
    }

    pub fn allow<I>(&mut self, syscalls: I) -> &mut Self
    where
        I: IntoIterator<Item = i32>,
    {
        for sysno in syscalls {
            self.insert(sysno, Action::Allow, Priority::Allow);
        }
        self
    }

    pub fn deny<I>(&mut self, syscalls: I, action: Action) -> &mut Self
    where
        I: IntoIterator<Item = i32>,
    {
        for sysno in syscalls {
            self.insert(sysno, action, Priority::Deny);
        }
        self
    }

    pub fn rule(&mut self, sysno: i32, action: Action) -> &mut Self {
        self.insert(sysno, action, Priority::Rule);
        self
    }

    pub fn conditional_rule(&mut self, sysno: i32, action: Action, args: Vec<ArgCmp>) -> &mut Self {
        self.conditional_rules.push(Rule {
            syscall: sysno,
            action,
            args,
        });
        self
    }

    pub fn build(self) -> Policy {
        let mut rules: Vec<Rule> = self
            .rules
            .into_iter()
            .map(|(syscall, pending)| Rule {
                syscall,
                action: pending.action,
                args: Vec::new(),
            })
            .collect();
        rules.extend(self.conditional_rules);
        rules.sort_by_key(|rule| rule.syscall);

        Policy {
            default_action: self.default_action,
            rules,
        }
    }

    fn insert(&mut self, sysno: i32, action: Action, priority: Priority) {
        match self.rules.get(&sysno) {
            Some(existing) => {
                if priority >= existing.priority {
                    self.rules.insert(sysno, PendingRule { action, priority });
                }
            }
            None => {
                self.rules.insert(sysno, PendingRule { action, priority });
            }
        }
    }
}

pub fn apply_to_self(policy: &Policy, options: ApplyOptions) -> Result<AppliedFilter> {
    let default_action = to_scmp_action(policy.default_action)?;
    let mut ctx = ScmpFilterContext::new(default_action)?;

    ctx.set_ctl_nnp(options.no_new_privs)?;

    if options.tsync {
        ctx.set_ctl_tsync(true)?;
    }

    #[cfg(target_arch = "x86_64")]
    {
        ctx.set_act_badarch(ScmpAction::KillProcess)?;
        if !ctx.is_arch_present(ScmpArch::X8664)? {
            ctx.add_arch(ScmpArch::X8664)?;
        }
        if ctx.is_arch_present(ScmpArch::X86)? {
            ctx.remove_arch(ScmpArch::X86)?;
        }
        if ctx.is_arch_present(ScmpArch::X32)? {
            ctx.remove_arch(ScmpArch::X32)?;
        }
    }

    for rule in &policy.rules {
        let action = to_scmp_action(rule.action)?;
        let syscall = ScmpSyscall::from_raw_syscall(rule.syscall as libseccomp::RawSyscall);
        if rule.args.is_empty() {
            ctx.add_rule(action, syscall)?;
        } else {
            let comparators: Vec<ScmpArgCompare> = rule.args.iter()
                .map(to_scmp_arg_compare)
                .collect();
            ctx.add_rule_conditional(action, syscall, &comparators)?;
        }
    }

    ctx.load()?;

    let listener_fd = if options.new_listener {
        let fd = ctx.get_notify_fd()?;
        // Duplicate because libseccomp retains ownership of the original notify fd.
        let dup_fd = unsafe { libc::dup(fd) };
        if dup_fd < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Some(unsafe { OwnedFd::from_raw_fd(dup_fd) })
    } else {
        None
    };

    Ok(AppliedFilter { listener_fd })
}

fn to_scmp_action(action: Action) -> Result<ScmpAction> {
    let scmp_action = match action {
        Action::Allow => ScmpAction::Allow,
        Action::Errno(errno) => ScmpAction::Errno(errno as i32),
        Action::KillProcess => ScmpAction::KillProcess,
        Action::Log => ScmpAction::Log,
        Action::UserNotif => ScmpAction::Notify,
    };
    Ok(scmp_action)
}

fn to_scmp_arg_compare(arg: &ArgCmp) -> ScmpArgCompare {
    let op = match arg.op {
        CmpOp::NotEqual => ScmpCompareOp::NotEqual,
        CmpOp::Less => ScmpCompareOp::Less,
        CmpOp::LessOrEqual => ScmpCompareOp::LessOrEqual,
        CmpOp::Equal => ScmpCompareOp::Equal,
        CmpOp::GreaterEqual => ScmpCompareOp::GreaterEqual,
        CmpOp::Greater => ScmpCompareOp::Greater,
        CmpOp::MaskedEqual { mask } => ScmpCompareOp::MaskedEqual(mask),
    };
    ScmpArgCompare::new(arg.arg, op, arg.value)
}
