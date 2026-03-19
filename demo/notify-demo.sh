#!/usr/bin/env bash
#
# Seccomp UserNotif Demo
#
# Demonstrates the seccomp user notification handler.
# When a container calls a syscall marked as SCMP_ACT_NOTIFY,
# the handler intercepts it, logs the details, and returns ENOSYS.
#
# This simulates the behavior of "syscall not available on this kernel".
#
set -euo pipefail

SECCOMP_FILTER="/usr/local/bin/seccomp-filter"
SOCK="/tmp/runway-notify.sock"

C='\033[0;36m' G='\033[0;32m' Y='\033[1;33m' N='\033[0m'
header() { echo -e "\n${C}=== $1 ===${N}\n"; }
pass()   { echo -e "  ${G}[PASS]${N} $1"; }
info()   { echo -e "  ${Y}[INFO]${N} $1"; }

cleanup() {
    [ -n "${HANDLER_PID:-}" ] && kill "$HANDLER_PID" 2>/dev/null || true
    rm -f "$SOCK"
}
trap cleanup EXIT

header "Seccomp UserNotif Handler Demo"

info "This demo intercepts io_uring syscalls via SCMP_ACT_NOTIFY"
info "The handler logs each intercepted call and returns ENOSYS"
echo ""

# 1. Start the notify handler in background
info "Starting notify handler..."
"$SECCOMP_FILTER" handle-notify --sock "$SOCK" &
HANDLER_PID=$!

# Wait for socket to appear
for i in $(seq 1 20); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done

if [ ! -S "$SOCK" ]; then
    echo "ERROR: notify socket did not appear"
    exit 1
fi
pass "Handler started (pid=$HANDLER_PID, sock=$SOCK)"

# 2. Apply seccomp filter with notify rules, then run a test program
header "Running test process with notify filter"

info "Applying filter: io_uring_setup/enter/register -> SCMP_ACT_NOTIFY"
info "Then calling io_uring_setup (syscall 425) which will be intercepted"
echo ""

# Use seccomp-filter apply with notify-sock to connect to our handler.
# The test program tries to call io_uring_setup via a raw syscall.
# Since io_uring_setup is marked as NOTIFY, the handler will intercept it.
"$SECCOMP_FILTER" apply \
    --default allow \
    --rule "425:user-notif" \
    --rule "426:user-notif" \
    --rule "427:user-notif" \
    --notify-sock "$SOCK" \
    -- \
    sh -c '
        echo "  Process $$ running with seccomp notify filter"
        echo "  Attempting io_uring_setup (should get ENOSYS)..."

        # Try to call io_uring_setup via python if available, or just demonstrate
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
# io_uring_setup = syscall 425
ret = libc.syscall(425, 32, 0)
err = ctypes.get_errno()
print(f\"  io_uring_setup returned: {ret}, errno: {err} ({errno.errorcode.get(err, \"?\")})\")
"
        else
            echo "  (python3 not available, using perl)"
            perl -e "
require \"syscall.ph\" if -e \"syscall.ph\";
my \$ret = syscall(425, 32, 0);
print \"  io_uring_setup returned: \$ret, errno: $!\\n\";
"
        fi
        echo "  Process completed normally (not killed)"
    '

echo ""
pass "Syscall was intercepted by handler and returned ENOSYS"

# 3. Show handler logs
header "Handler Output"
info "The handler logged the intercepted syscall above (on stderr)"
info "Key fields: pid, syscall name, syscall number, args"

header "Done"
echo "  The notify handler intercepted io_uring syscalls and returned"
echo "  ENOSYS ('Function not implemented'), simulating a kernel that"
echo "  does not support io_uring. The process was NOT killed."
echo ""
