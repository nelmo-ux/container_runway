#!/bin/bash
# Docker停止とランタイムプロセスのクリーンアップ

set -e

echo "=== Stopping Docker and cleaning up runtime processes ==="
echo ""

# Dockerサービスを停止
echo "Step 1: Stopping Docker daemon..."
sudo systemctl stop docker || sudo service docker stop || echo "Docker may not be running via systemd"

# Docker関連プロセスが完全に停止するまで待機
echo "Waiting for Docker to stop..."
sleep 3

# 残存するruntimeプロセスを確認
echo ""
echo "Step 2: Checking for remaining runtime processes..."
if pgrep -f "/usr/local/bin/runtime" > /dev/null; then
    echo "Found runtime processes:"
    ps aux | grep -E "[/]usr/local/bin/runtime" || true
    echo ""
    echo "Killing remaining runtime processes..."
    sudo pkill -9 -f "/usr/local/bin/runtime" || true
    sleep 2
else
    echo "No runtime processes found"
fi

# containerdプロセスも確認
echo ""
echo "Step 3: Checking containerd..."
if pgrep containerd > /dev/null; then
    echo "Stopping containerd..."
    sudo systemctl stop containerd || sudo pkill containerd || true
    sleep 2
fi

# 最終確認
echo ""
echo "Step 4: Final verification..."
if lsof /usr/local/bin/runtime 2>/dev/null; then
    echo "WARNING: Binary still in use by:"
    lsof /usr/local/bin/runtime
    echo ""
    echo "Attempting force cleanup..."
    sudo fuser -k /usr/local/bin/runtime || true
    sleep 1
else
    echo "✓ Binary is no longer in use"
fi

echo ""
echo "=== Cleanup complete ==="
echo "You can now run: ./01-rebuild-debug.sh"
echo ""
echo "To restart Docker after installation:"
echo "  sudo systemctl start docker"
