#!/bin/bash
# Configure Docker to use Runway runtime

set -e

echo "=== Docker Configuration for Runway Runtime ==="
echo ""

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

DAEMON_JSON="/etc/docker/daemon.json"
BACKUP_JSON="/etc/docker/daemon.json.backup-$(date +%Y%m%d-%H%M%S)"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

echo "Step 1: Backing up existing Docker configuration..."
if [ -f "$DAEMON_JSON" ]; then
    cp "$DAEMON_JSON" "$BACKUP_JSON"
    echo "  ✓ Backup created at $BACKUP_JSON"
else
    echo "  ℹ No existing configuration found"
fi

echo ""
echo "Step 2: Updating Docker daemon configuration..."

# Create or update daemon.json
if [ -f "$DAEMON_JSON" ]; then
    # Parse existing JSON and add runway runtime
    python3 -c "
import json
import sys

try:
    with open('$DAEMON_JSON', 'r') as f:
        config = json.load(f)
except:
    config = {}

if 'runtimes' not in config:
    config['runtimes'] = {}

config['runtimes']['runway'] = {
    'path': '/usr/local/bin/runtime',
    'runtimeArgs': ['--root', '/run/runway']
}

with open('$DAEMON_JSON', 'w') as f:
    json.dump(config, f, indent=2)
" 2>/dev/null || {
    # Fallback: simple replacement
    cat > "$DAEMON_JSON" <<EOF
{
  "runtimes": {
    "runway": {
      "path": "/usr/local/bin/runtime",
      "runtimeArgs": ["--root", "/run/runway"]
    }
  }
}
EOF
}
else
    # Create new daemon.json
    cat > "$DAEMON_JSON" <<EOF
{
  "runtimes": {
    "runway": {
      "path": "/usr/local/bin/runtime",
      "runtimeArgs": ["--root", "/run/runway"]
    }
  }
}
EOF
fi

echo "  ✓ Configuration updated"

echo ""
echo "Step 3: Restarting Docker daemon..."
if systemctl is-active --quiet docker; then
    systemctl restart docker
    sleep 2
    echo "  ✓ Docker daemon restarted"
else
    echo "  ℹ Docker daemon is not running via systemd"
    echo "    Please restart Docker manually"
fi

echo ""
echo "Step 4: Verifying runtime registration..."
if docker info 2>/dev/null | grep -q "runway"; then
    echo "  ✓ Runway runtime is registered"
    docker info | grep -A 5 "Runtimes:"
else
    echo "  ✗ Runway runtime not found in Docker info"
    echo "    Please check Docker logs and configuration"
    exit 1
fi

echo ""
echo "=== Configuration Complete ==="
echo ""
echo "You can now use Runway runtime with:"
echo "  docker run --runtime=runway busybox echo 'Hello from Runway!'"
echo ""
