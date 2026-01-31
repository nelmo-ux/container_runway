#!/bin/bash
# ステップ2: コアダンプの有効化（デバッグ用）

set -e

echo "=== Enabling core dumps for debugging ==="

# 現在の設定を確認
echo "Current ulimit -c: $(ulimit -c)"

# コアダンプを有効化
echo "Enabling unlimited core dumps..."
ulimit -c unlimited

# コアダンプのパターンを設定（要sudo）
echo ""
echo "Setting core dump pattern (requires sudo)..."
sudo sysctl -w kernel.core_pattern=/tmp/core-%e-%p-%t

# 確認
echo ""
echo "New ulimit -c: $(ulimit -c)"
echo "Core pattern: $(cat /proc/sys/kernel/core_pattern)"

echo ""
echo "=== Core dumps enabled ==="
echo "Core files will be saved to: /tmp/core-runtime-*"
echo ""
echo "To analyze a core dump:"
echo "  gdb /usr/local/bin/runtime /tmp/core-runtime-<pid>-<timestamp>"
