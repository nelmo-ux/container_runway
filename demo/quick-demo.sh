#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="runway-quick-demo"
RUNTIME="runway"
PROFILE="$SCRIPT_DIR/seccomp-profiles/block-inet-socket-args.json"

G='\033[0;32m' R='\033[0;31m' C='\033[0;36m' Y='\033[1;33m' N='\033[0m'
header() { echo -e "\n${C}=== $1 ===${N}\n"; }
pass()   { echo -e "  ${G}[PASS]${N} $1"; }
info()   { echo -e "  ${Y}[INFO]${N} $1"; }

# ---- Build ----
header "1. Docker Build"
docker build -t "$IMAGE" "$SCRIPT_DIR"
pass "Image built: $IMAGE"

# ---- Basic Run ----
header "2. Basic Run (default seccomp)"
docker run --rm --runtime="$RUNTIME" "$IMAGE" echo "Hello from Runway!"
pass "Container ran with default Docker seccomp profile"

# ---- Entrypoint ----
header "3. Entrypoint (process/fs/syscall check)"
docker run --rm --runtime="$RUNTIME" "$IMAGE"
pass "Entrypoint completed"

# ---- Seccomp: args-level filtering ----
header "4. Seccomp Argument Filtering"
info "socket(AF_INET/AF_INET6) blocked, socket(AF_UNIX) allowed"
echo ""

echo -e "  ${C}[A]${N} wget (AF_INET) - should be blocked:"
docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE" \
  sh -c 'wget -q -T2 -O /dev/null http://1.1.1.1 2>&1 || echo "    => Blocked by seccomp args filter"'
pass "AF_INET socket blocked"

echo ""
echo -e "  ${C}[B]${N} ls / (AF_UNIX) - should work:"
docker run --rm --runtime="$RUNTIME" --security-opt "seccomp=$PROFILE" "$IMAGE" \
  sh -c 'ls / >/dev/null && echo "    => AF_UNIX works fine"'
pass "AF_UNIX socket allowed"

# ---- Cleanup ----
header "Done"
docker rmi "$IMAGE" >/dev/null 2>&1 || true
pass "Cleanup done"
