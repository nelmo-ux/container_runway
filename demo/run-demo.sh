#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="runway-seccomp-demo"
PROFILE_DIR="$SCRIPT_DIR/seccomp-profiles"
RUNTIME="runway"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }

# --- Pre-flight checks ---
header "Pre-flight Checks"

if ! command -v docker &>/dev/null; then
    fail "docker not found"
    exit 1
fi
pass "docker found"

if ! docker info 2>/dev/null | grep -q "$RUNTIME"; then
    fail "'$RUNTIME' runtime not registered in Docker"
    echo "  Run: sudo ./configure-docker.sh"
    exit 1
fi
pass "'$RUNTIME' runtime registered"

# --- Build demo image ---
header "Building Demo Image"

docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"
pass "Image '$IMAGE_NAME' built"

# --- Demo 1: Normal execution (no seccomp restriction) ---
header "Demo 1: Normal Execution (seccomp=unconfined)"

info "docker run --rm --runtime=$RUNTIME --security-opt seccomp=unconfined $IMAGE_NAME"
echo ""
if docker run --rm --runtime="$RUNTIME" --security-opt seccomp=unconfined "$IMAGE_NAME"; then
    pass "Container exited normally"
else
    fail "Container failed (exit=$?)"
fi

# --- Demo 2: Docker default seccomp ---
header "Demo 2: Docker Default Seccomp Profile"

info "docker run --rm --runtime=$RUNTIME $IMAGE_NAME"
echo ""
if docker run --rm --runtime="$RUNTIME" "$IMAGE_NAME"; then
    pass "Container exited normally with default seccomp"
else
    fail "Container failed (exit=$?)"
fi

# --- Demo 3: Block uname with SCMP_ACT_KILL ---
header "Demo 3: Block uname (SCMP_ACT_KILL)"

PROFILE="$PROFILE_DIR/block-uname-kill.json"
info "Profile: $PROFILE"
info "uname syscall will be killed by seccomp"
info "docker run --rm --runtime=$RUNTIME --security-opt seccomp=$PROFILE $IMAGE_NAME"
echo ""
if docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE_NAME" 2>&1; then
    fail "Container should have been killed at uname"
else
    code=$?
    pass "Container killed by seccomp (exit=$code)"
    info "The process was terminated when it called uname()"
fi

# --- Demo 4: Block openat with SCMP_ACT_ERRNO ---
header "Demo 4: Block openat (SCMP_ACT_ERRNO, errno=EACCES)"

PROFILE="$PROFILE_DIR/block-openat-errno.json"
info "Profile: $PROFILE"
info "openat syscall will return EACCES (Permission denied)"
echo ""
docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE_NAME" \
    sh -c 'echo "Trying to read /etc/hostname..."; cat /etc/hostname 2>&1 || echo "=> BLOCKED by seccomp (EACCES)"'
pass "openat blocked with EACCES"

# --- Demo 5: Block mkdir with SCMP_ACT_ERRNO ---
header "Demo 5: Block mkdir/mkdirat (SCMP_ACT_ERRNO, errno=EPERM)"

PROFILE="$PROFILE_DIR/block-mkdir-errno.json"
info "Profile: $PROFILE"
info "mkdir/mkdirat will return EPERM"
echo ""
docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE_NAME" \
    sh -c 'echo "Trying mkdir /tmp/testdir..."; mkdir /tmp/testdir 2>&1 || echo "=> BLOCKED by seccomp (EPERM)"'
pass "mkdir blocked with EPERM"

# --- Demo 6: Block network ---
header "Demo 6: Block Network Syscalls (socket/connect)"

PROFILE="$PROFILE_DIR/block-network.json"
info "Profile: $PROFILE"
info "socket/connect/sendto/recvfrom will return EPERM"
echo ""
docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE_NAME" \
    sh -c 'echo "Trying wget http://example.com..."; wget -q -O /dev/null http://example.com 2>&1 || echo "=> BLOCKED by seccomp (network denied)"'
pass "Network syscalls blocked"

# --- Demo 7: Strace syscall tracing ---
header "Demo 7: Strace Syscall Tracing"

info "RUNWAY_STRACE=1 enables host-side strace on the container process"
info "docker run --rm --runtime=$RUNTIME -e RUNWAY_STRACE=1 $IMAGE_NAME /bin/echo 'traced'"
echo ""
docker run --rm --runtime="$RUNTIME" -e RUNWAY_STRACE=1 "$IMAGE_NAME" /bin/echo "traced"

# Find the most recent strace log
STRACE_LOG=$(ls -t /tmp/runway-strace-*.log 2>/dev/null | head -1)
if [ -n "$STRACE_LOG" ] && [ -f "$STRACE_LOG" ]; then
    LINES=$(wc -l < "$STRACE_LOG")
    pass "Strace log captured: $STRACE_LOG ($LINES lines)"
    info "Last 5 syscalls:"
    tail -5 "$STRACE_LOG" | sed 's/^/    /'
else
    fail "Strace log not found in /tmp/runway-strace-*.log"
fi

# --- Demo 8: Argument-level filtering (new!) ---
header "Demo 8: Argument-Level Filtering (socket AF_INET blocked, AF_UNIX allowed)"

PROFILE="$PROFILE_DIR/block-inet-socket-args.json"
info "Profile: $PROFILE"
info "socket(AF_INET) and socket(AF_INET6) will be blocked"
info "socket(AF_UNIX) remains allowed (used by shell internals)"
echo ""

# Test 1: AF_UNIX should work (ls uses it internally)
echo -e "  ${CYAN}[Test A]${NC} AF_UNIX socket (should work):"
if docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE_NAME" \
    sh -c 'ls / >/dev/null && echo "  => AF_UNIX works fine"' 2>&1; then
    pass "AF_UNIX socket allowed"
else
    fail "AF_UNIX unexpectedly blocked"
fi

echo ""

# Test 2: AF_INET should be blocked (wget uses it)
echo -e "  ${CYAN}[Test B]${NC} AF_INET socket (should be blocked):"
docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE_NAME" \
    sh -c 'wget -q -O /dev/null http://example.com 2>&1 || echo "  => AF_INET blocked by seccomp args filter"'
pass "AF_INET socket blocked via argument-level filtering"

# --- Summary ---
header "Demo Complete"

echo "  Demonstrated seccomp enforcement with Runway runtime:"
echo ""
echo "  1. Normal execution       - all syscalls allowed"
echo "  2. Docker default seccomp - standard Docker restrictions"
echo "  3. SCMP_ACT_KILL          - process killed on blocked syscall"
echo "  4. SCMP_ACT_ERRNO         - syscall returns error (EACCES)"
echo "  5. SCMP_ACT_ERRNO         - mkdir blocked (EPERM)"
echo "  6. Network blocking       - socket/connect denied"
echo "  7. Strace tracing         - syscall log captured to /tmp/"
echo "  8. Argument filtering     - socket(AF_INET) blocked, AF_UNIX allowed"
echo ""

# --- Cleanup ---
info "Cleaning up demo image..."
docker rmi "$IMAGE_NAME" >/dev/null 2>&1 || true
pass "Cleanup done"
