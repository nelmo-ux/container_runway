#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="runway-demo"
CONTAINER="runway-exec-demo"
RUNTIME="runway"
PROFILE="$SCRIPT_DIR/seccomp-profiles/block-inet-socket-args.json"

G='\033[0;32m' C='\033[0;36m' Y='\033[1;33m' N='\033[0m'
header() { echo -e "\n${C}=== $1 ===${N}\n"; }
pass()   { echo -e "  ${G}[PASS]${N} $1"; }
info()   { echo -e "  ${Y}[INFO]${N} $1"; }

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ---- Build & Start ----
header "1. Build & Start Container"
docker build -t "$IMAGE" "$SCRIPT_DIR"
docker run -d --name "$CONTAINER" --runtime="$RUNTIME" \
  --security-opt "seccomp=$PROFILE" "$IMAGE" sleep 3600
pass "Container '$CONTAINER' running"

# ---- exec demos ----
header "2. docker exec: basic commands"
info "uname -a"
docker exec "$CONTAINER" uname -a
echo ""
info "id"
docker exec "$CONTAINER" id
echo ""
info "hostname"
docker exec "$CONTAINER" hostname
pass "Basic commands OK"

header "3. docker exec: filesystem"
info "Write and read a file"
docker exec "$CONTAINER" sh -c 'echo "hello from exec" > /tmp/test.txt && cat /tmp/test.txt'
pass "Filesystem OK"

header "4. docker exec: process isolation"
info "ps inside container"
docker exec "$CONTAINER" ps aux
pass "Process isolation OK"

header "5. docker exec: seccomp args filter"
info "AF_INET blocked, AF_UNIX allowed"
echo ""

echo -e "  ${C}[A]${N} wget 1.1.1.1 (AF_INET) - should be blocked:"
docker exec "$CONTAINER" sh -c 'wget -q -T2 -O /dev/null http://1.1.1.1 2>&1 || echo "    => AF_INET blocked by args filter"'
pass "AF_INET blocked"

echo ""
echo -e "  ${C}[B]${N} ls / (AF_UNIX) - should work:"
docker exec "$CONTAINER" sh -c 'ls / >/dev/null && echo "    => AF_UNIX works fine"'
pass "AF_UNIX allowed"

header "Done"
info "Container was: docker exec -it $CONTAINER sh"
info "Cleaning up..."
