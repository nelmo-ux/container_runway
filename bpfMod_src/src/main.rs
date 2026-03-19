use std::io::{IoSlice, IoSliceMut};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use libseccomp::{ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use nix::cmsg_space;
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags, UnixAddr};
use seccomp_filter::{
    apply_to_self, load_oci_seccomp_policy, load_policy, Action, ApplyOptions, Error, Policy,
    PolicyAction, PolicyBuilder, PolicyFile, Result,
};

const DEFAULT_ERRNO: u16 = 1; // EPERM

#[derive(Parser, Debug)]
#[command(name = "seccomp-filter", version, about = "Apply cooperative seccomp filters")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Apply(ApplyArgs),
    HandleNotify(HandleNotifyArgs),
}

#[derive(Parser, Debug)]
struct HandleNotifyArgs {
    /// Path to UNIX socket to listen on for incoming notify fd
    #[arg(long)]
    sock: PathBuf,
}

#[derive(Parser, Debug)]
struct ApplyArgs {
    /// PID of the current process (cooperative guard)
    #[arg(long)]
    pid: Option<u32>,

    /// Comma-separated syscall numbers to allow
    #[arg(long)]
    allow: Option<String>,

    /// Comma-separated syscall numbers to deny
    #[arg(long)]
    deny: Option<String>,

    /// Per-syscall override rule: <sysno>:<action>[:<errno>]
    #[arg(long)]
    rule: Vec<String>,

    /// Default action for --deny list
    #[arg(long, value_enum, default_value_t = DenyActionArg::Errno)]
    action: DenyActionArg,

    /// Errno value for ERRNO actions
    #[arg(long, default_value_t = DEFAULT_ERRNO)]
    errno: u16,

    /// Default action when no rule matches
    #[arg(long, value_enum)]
    default: Option<DefaultActionArg>,

    /// Path to UNIX socket for user-notif listener handoff
    #[arg(long)]
    notify_sock: Option<PathBuf>,

    /// JSON policy file (shared with notify receiver)
    #[arg(long)]
    policy: Option<PathBuf>,

    /// OCI config.json (linux.seccomp) to convert and apply
    #[arg(long)]
    oci_config: Option<PathBuf>,

    /// Sync filter to all threads in the process
    #[arg(long)]
    tsync: bool,

    /// Command to exec after applying the filter
    #[arg(num_args = 0.., trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum DenyActionArg {
    Errno,
    Kill,
    Log,
    UserNotif,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum DefaultActionArg {
    Allow,
    Errno,
    Kill,
    Log,
    UserNotif,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Apply(args) => apply_command(args),
        Commands::HandleNotify(args) => handle_notify_command(args),
    }
}

fn apply_command(args: ApplyArgs) -> Result<()> {
    if let Some(pid) = args.pid {
        let current = std::process::id();
        if pid != current {
            return Err(Error::PidMismatch {
                expected: current,
                actual: pid,
            });
        }
    }

    let (policy, oci_tsync, oci_notify) = if let Some(path) = &args.oci_config {
        ensure_no_conflicting_flags(&args)?;
        let oci_policy = load_oci_seccomp_policy(path)?;
        (oci_policy.policy, oci_policy.tsync, oci_policy.notify_sock)
    } else {
        (build_policy(&args)?, false, None)
    };

    let needs_notify = policy
        .rules
        .iter()
        .any(|rule| matches!(rule.action, Action::UserNotif))
        || matches!(policy.default_action, Action::UserNotif);

    let notify_sock = if args.notify_sock.is_some() {
        args.notify_sock.clone()
    } else {
        oci_notify
    };

    if needs_notify && notify_sock.is_none() {
        return Err(Error::NotifySockRequired);
    }

    let options = ApplyOptions {
        tsync: args.tsync || oci_tsync,
        no_new_privs: true,
        new_listener: needs_notify,
    };

    let applied = apply_to_self(&policy, options)?;

    if needs_notify {
        let sock_path = notify_sock
            .as_ref()
            .ok_or(Error::NotifySockRequired)?;
        let listener = applied
            .listener_fd
            .as_ref()
            .ok_or(Error::NotifyListenerMissing)?;
        send_notify_fd(sock_path, listener.as_raw_fd())?;
    }

    if args.command.is_empty() {
        return Ok(());
    }

    exec_command(args.command)
}

fn ensure_no_conflicting_flags(args: &ApplyArgs) -> Result<()> {
    if args.policy.is_some()
        || args.allow.is_some()
        || args.deny.is_some()
        || !args.rule.is_empty()
        || args.default.is_some()
        || args.action != DenyActionArg::Errno
        || args.errno != DEFAULT_ERRNO
    {
        return Err(Error::OciSeccomp(
            "--oci-config cannot be combined with policy/rules/default/action/errno flags"
                .to_string(),
        ));
    }
    Ok(())
}

fn exec_command(command: Vec<String>) -> Result<()> {
    let mut cmd_iter = command.into_iter();
    let program = match cmd_iter.next() {
        Some(program) => program,
        None => return Ok(()),
    };

    let err = std::process::Command::new(&program)
        .args(cmd_iter)
        .exec();

    Err(Error::ExecFailed(format!(
        "failed to exec {program}: {err}"
    )))
}

fn send_notify_fd(sock_path: &PathBuf, fd: i32) -> Result<()> {
    let stream = UnixStream::connect(sock_path)?;
    let iov = [IoSlice::new(&[0u8])];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg(
        stream.as_raw_fd(),
        &iov,
        &cmsg,
        MsgFlags::empty(),
        None::<&UnixAddr>,
    )?;
    Ok(())
}

fn build_policy(args: &ApplyArgs) -> Result<Policy> {
    let mut policy_file: Option<PolicyFile> = None;
    let mut effective_default = Action::Allow;

    if let Some(path) = args.policy.as_ref() {
        let policy = load_policy(path).map_err(|err| Error::PolicyLoad(err.to_string()))?;
        if let Some(default) = &policy.default {
            effective_default = policy_action_to_action(default.action, default.errno, args.errno)?;
        }
        policy_file = Some(policy);
    }

    if let Some(default_arg) = args.default {
        effective_default = default_action(default_arg, args.errno)?;
    }

    let deny_action = deny_action(args.action, args.errno)?;

    let mut builder = PolicyBuilder::new(effective_default);

    if let Some(policy) = &policy_file {
        apply_policy_rules(&mut builder, policy, args.errno)?;
    }

    if let Some(ref allow) = args.allow {
        let syscalls = parse_syscall_list(allow)?;
        builder.allow(syscalls);
    }

    if let Some(ref deny) = args.deny {
        let syscalls = parse_syscall_list(deny)?;
        builder.deny(syscalls, deny_action);
    }

    for rule in &args.rule {
        let (sysno, action) = parse_rule(rule, args.errno)?;
        builder.rule(sysno, action);
    }

    Ok(builder.build())
}

fn apply_policy_rules(
    builder: &mut PolicyBuilder,
    policy: &PolicyFile,
    fallback_errno: u16,
) -> Result<()> {
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    let policy_default_errno = policy
        .default
        .as_ref()
        .and_then(|def| def.errno)
        .unwrap_or(fallback_errno as i32);

    for rule in &policy.rules {
        match rule.action {
            PolicyAction::Allow => allow.push(rule.sysno),
            PolicyAction::Deny | PolicyAction::Errno => {
                let errno = rule.errno.unwrap_or(policy_default_errno);
                if errno != fallback_errno as i32 {
                    if errno <= 0 || errno > u16::MAX as i32 {
                        return Err(Error::InvalidErrno(errno as u16));
                    }
                    builder.rule(rule.sysno, Action::Errno(errno as u16));
                } else {
                    deny.push(rule.sysno);
                }
            }
        }
    }

    if !allow.is_empty() {
        builder.allow(allow);
    }

    if !deny.is_empty() {
        builder.deny(deny, Action::Errno(fallback_errno));
    }

    Ok(())
}

fn policy_action_to_action(
    action: PolicyAction,
    errno: Option<i32>,
    fallback_errno: u16,
) -> Result<Action> {
    match action {
        PolicyAction::Allow => Ok(Action::Allow),
        PolicyAction::Deny | PolicyAction::Errno => {
            let errno = errno.unwrap_or(fallback_errno as i32);
            if errno <= 0 || errno > u16::MAX as i32 {
                return Err(Error::InvalidErrno(errno as u16));
            }
            Ok(Action::Errno(errno as u16))
        }
    }
}

fn parse_syscall_list(list: &str) -> Result<Vec<i32>> {
    if list.trim().is_empty() {
        return Ok(Vec::new());
    }

    list.split(',')
        .map(|item| parse_syscall(item.trim()))
        .collect()
}

fn parse_syscall(value: &str) -> Result<i32> {
    if value.is_empty() {
        return Err(Error::InvalidSyscall(value.to_string()));
    }

    value
        .parse::<i32>()
        .map_err(|_| Error::InvalidSyscall(value.to_string()))
}

fn deny_action(action: DenyActionArg, errno: u16) -> Result<Action> {
    match action {
        DenyActionArg::Errno => action_errno(errno),
        DenyActionArg::Kill => Ok(Action::KillProcess),
        DenyActionArg::Log => Ok(Action::Log),
        DenyActionArg::UserNotif => Ok(Action::UserNotif),
    }
}

fn default_action(action: DefaultActionArg, errno: u16) -> Result<Action> {
    match action {
        DefaultActionArg::Allow => Ok(Action::Allow),
        DefaultActionArg::Errno => action_errno(errno),
        DefaultActionArg::Kill => Ok(Action::KillProcess),
        DefaultActionArg::Log => Ok(Action::Log),
        DefaultActionArg::UserNotif => Ok(Action::UserNotif),
    }
}

fn action_errno(errno: u16) -> Result<Action> {
    if errno == 0 {
        return Err(Error::InvalidErrno(errno));
    }
    Ok(Action::Errno(errno))
}

fn parse_rule(rule: &str, fallback_errno: u16) -> Result<(i32, Action)> {
    let parts: Vec<&str> = rule.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(Error::ParseRule(rule.to_string()));
    }

    let sysno = parse_syscall(parts[0].trim())?;
    let action = parse_action(parts[1].trim(), parts.get(2).copied(), fallback_errno)?;
    Ok((sysno, action))
}

fn parse_action(name: &str, errno_part: Option<&str>, fallback_errno: u16) -> Result<Action> {
    match name {
        "allow" => Ok(Action::Allow),
        "errno" => {
            let errno = match errno_part {
                Some(value) => value
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| Error::ParseRule(format!("invalid errno: {value}")))?,
                None => fallback_errno,
            };
            action_errno(errno)
        }
        "kill" => Ok(Action::KillProcess),
        "log" => Ok(Action::Log),
        "user-notif" => Ok(Action::UserNotif),
        _ => Err(Error::ParseRule(name.to_string())),
    }
}

// --- handle-notify subcommand ---

fn handle_notify_command(args: HandleNotifyArgs) -> Result<()> {
    let sock_path = &args.sock;

    // Clean up stale socket file
    let _ = std::fs::remove_file(sock_path);

    let listener = UnixListener::bind(sock_path).map_err(|e| {
        Error::OciSeccomp(format!("failed to bind notify socket {}: {}", sock_path.display(), e))
    })?;

    eprintln!("seccomp-notify: ソケット {} で待ち受け中...", sock_path.display());

    // Accept one connection and receive the notify fd
    let (stream, _) = listener.accept().map_err(|e| {
        Error::OciSeccomp(format!("accept failed: {}", e))
    })?;

    let notify_fd = receive_notify_fd(&stream)?;
    eprintln!("seccomp-notify: notify fd={} を受信しました", notify_fd);

    // Clean up socket file
    let _ = std::fs::remove_file(sock_path);

    // Handle notifications in a loop
    run_notify_loop(notify_fd)
}

fn receive_notify_fd(stream: &UnixStream) -> Result<i32> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = cmsg_space!([i32; 1]);

    let msg = recvmsg::<UnixAddr>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )?;

    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(fd);
            }
        }
    }

    Err(Error::NotifyListenerMissing)
}

fn run_notify_loop(notify_fd: i32) -> Result<()> {
    eprintln!("seccomp-notify: ハンドラ待機中...");

    loop {
        let req = match ScmpNotifReq::receive(notify_fd) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("seccomp-notify: 対象プロセスが終了しました ({})", e);
                break;
            }
        };

        let syscall_name = req.data.syscall
            .get_name()
            .unwrap_or_else(|_| format!("syscall#{}", req.data.syscall.as_raw_syscall()));

        eprintln!(
            "seccomp-notify: [警告] pid={} がシステムコール {}({}) を呼び出しましたが、このカーネルでは利用できません (ENOSYS) | args=[{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
            req.pid,
            syscall_name,
            req.data.syscall.as_raw_syscall(),
            req.data.args[0],
            req.data.args[1],
            req.data.args[2],
            req.data.args[3],
            req.data.args[4],
            req.data.args[5],
        );

        // ENOSYS（「機能が実装されていない」）で応答
        let resp = ScmpNotifResp::new_error(req.id, -libc::ENOSYS, ScmpNotifRespFlags::empty());
        match resp.respond(notify_fd) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("seccomp-notify: 応答失敗 ({})", e);
                continue;
            }
        }
    }

    eprintln!("seccomp-notify: ハンドラを終了します");
    Ok(())
}
