# Container Runway: Known Incompatibilities with `runc`

This document captures the major gaps that prevent the current runtime (`runtime`) from acting as a drop‐in replacement for `runc` in Docker/containerd environments.

## 1. OCI Runtime Specification Compliance
- `state` output deviates from the OCI schema. It omits required fields such as `bundle`, `annotations`, `version`, and `ociVersion`, while introducing nonstandard keys like `bundle_path` (`main.cpp:227-244`).
- CLI support stops at `create/start/state/kill/delete`. Docker relies on additional OCI commands such as `run`, `exec`, `pause`, `resume`, `ps`, and `events`.
- Multiple OCI options are parsed only to be ignored (e.g., `--console-socket`, `--preserve-fds`, `--notify-socket`). Without console socket handling, TTY and exec session plumbing cannot function (`main.cpp:405-416`).

## 2. Process Setup Bugs
- Environment variables and working directory from `process.env` and `process.cwd` are parsed but never applied before `execvp`, so containers inherit the launcher’s environment and always start in `/` (`main.cpp:365-390`).
- Argument vectors are built on the parent stack and freed before the child calls `execvp`, leaving dangling pointers (`main.cpp:442-448`). This leads to undefined behaviour during process launch.

## 3. Namespace & User Handling
- When `CLONE_NEWUSER` is requested, the runtime does not configure `/proc/[pid]/{uid,gid}_map`, causing `clone` to fail immediately. Namespace `path` entries are parsed but ignored (`main.cpp:145-149`, `main.cpp:451-458`).
- Execution requires a real root user (`getuid() != 0` aborts), preventing rootless Docker support (`main.cpp:762-764`).

## 4. Filesystem Isolation
- The runtime ignores OCI `mounts`, `devices`, `maskedPaths`, `readonlyPaths`, `rootfsPropagation`, and volume options; it only performs `chroot` and a `/proc` mount (`main.cpp:369-383`).
- `pivot_root` is not implemented, so the host root remains accessible via `/proc/*/root`.

## 5. Resource Management & Security
- Cgroup handling is hard-coded to cgroup v1 paths under `/sys/fs/cgroup/{memory,cpu}/my_runtime/<id>` and ignores `linux.cgroupsPath`, cgroup v2, and systemd delegation (`main.cpp:303-333`, `main.cpp:741-744`).
- Mandatory isolation features from OCI `linux` are unimplemented (capabilities, securebits, `noNewPrivileges`, rlimits, seccomp, AppArmor/SELinux labels, etc.).

## 6. Operational Gaps
- Logging, lifecycle hooks (`prestart`, `poststart`, `poststop`), and event reporting are absent, so containerd/Docker cannot observe or manage container state transitions.
- No support for console handling (`--console-socket`) or `--preserve-fds`, making interactive/attach scenarios impossible.

## Recommended Next Steps
1. Align command surface and JSON outputs with the OCI runtime spec (consult `opencontainers/runtime-tools` conformance tests).
2. Rework process spawning to honor `process` configuration and avoid stack lifetime issues.
3. Implement required namespace, UID/GID mapping, filesystem, and cgroup features; add security primitives per OCI `linux`.
4. Add proper logging, events, and hook execution to integrate smoothly with Docker/containerd.

Until these items are addressed, Docker will fail to treat this runtime as a viable `runc` replacement.
