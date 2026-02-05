#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME="$ROOT/runtime"
BPFMOD="$ROOT/../bpfMod"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required to build seccomp-filter" >&2
  exit 1
fi

if [ ! -x "$RUNTIME" ]; then
  echo "runtime binary not found: $RUNTIME" >&2
  exit 1
fi

if [ ! -x "$BPFMOD/target/release/seccomp-filter" ]; then
  echo "building seccomp-filter..."
  (cd "$BPFMOD" && cargo build --release)
fi

bundle_dir="$ROOT/bundles/demo-seccomp-$(date +%Y%m%d%H%M%S)"
mkdir -p "$bundle_dir/rootfs"

echo "generating base config.json..."
"$RUNTIME" spec --bundle "$bundle_dir"

echo "preparing rootfs from ubuntu:22.04..."
image="ubuntu:22.04"
docker pull "$image" >/dev/null
cid=$(docker create "$image" sleep infinity)
docker start "$cid" >/dev/null
docker exec "$cid" bash -lc "apt-get update >/dev/null && apt-get install -y libseccomp2 >/dev/null"
docker export "$cid" | tar -C "$bundle_dir/rootfs" -xf -
docker rm -f "$cid" >/dev/null

echo "installing seccomp-filter into rootfs..."
install -m 0755 "$BPFMOD/target/release/seccomp-filter" \
  "$bundle_dir/rootfs/usr/local/bin/seccomp-filter"

echo "patching config.json for allow run..."
python3 - <<PY
import json
p = "$bundle_dir/config.json"
with open(p) as f:
    data = json.load(f)
data["process"]["terminal"] = False
data["process"]["args"] = ["/bin/sh", "-c", "echo ALLOW; /bin/ls / | head -n 3"]
data["process"]["cwd"] = "/"
data["root"]["readonly"] = False
with open(p, "w") as f:
    json.dump(data, f, indent=2)
PY

echo "== allow run =="
sudo "$RUNTIME" run --bundle "$bundle_dir" demo-allow

echo "patching config.json for seccomp deny..."
python3 - <<PY
import json
p = "$bundle_dir/config.json"
with open(p) as f:
    data = json.load(f)
data.setdefault("linux", {})
data["linux"]["seccomp"] = {
    "defaultAction": "SCMP_ACT_ALLOW",
    "errnoRet": 1,
    "syscalls": [
        {"names": ["openat"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}
    ]
}
data["process"]["args"] = ["/bin/sh", "-c", "echo DENY; /bin/ls /; echo done"]
with open(p, "w") as f:
    json.dump(data, f, indent=2)
PY

echo "== deny run (openat blocked) =="
sudo "$RUNTIME" run --bundle "$bundle_dir" demo-deny

echo "bundle created at: $bundle_dir"
