#!/bin/bash
# ステップ4: クラッシュの詳細分析

set -e

echo "=== Analyzing Runtime Crash ==="
echo ""

# カーネルログを確認
echo "1. Recent kernel messages about runtime crashes:"
echo "================================================"
dmesg | grep -i "runtime" | tail -20 || echo "(no messages found)"
echo ""

# セグメンテーションフォルトの詳細
echo "2. Segmentation fault details:"
echo "=============================="
dmesg | grep -E "(segfault|general protection|traps:.*runtime)" | tail -10 || echo "(no segfaults found)"
echo ""

# コアダンプの確認
echo "3. Core dump files:"
echo "==================="
if ls /tmp/core-runtime-* 2>/dev/null; then
    echo ""
    echo "Found core dumps. To analyze with gdb:"
    for core in /tmp/core-runtime-*; do
        echo "  gdb /usr/local/bin/runtime $core"
    done
else
    echo "(no core dumps found)"
    echo ""
    echo "To enable core dumps, run: ./02-enable-coredump.sh"
fi
echo ""

# Dockerログの確認
echo "4. Docker daemon logs:"
echo "======================"
echo "Checking for recent Docker errors..."
if command -v journalctl &> /dev/null; then
    sudo journalctl -u docker -n 20 --no-pager | grep -i "runway\|runtime\|error" || echo "(no relevant logs)"
else
    echo "(journalctl not available)"
fi
echo ""

# ランタイムの状態確認
echo "5. Runtime state:"
echo "================="
echo "Runtime binary: $(which runtime)"
echo "File type: $(file /usr/local/bin/runtime | cut -d: -f2-)"
echo "Permissions: $(ls -l /usr/local/bin/runtime | cut -d' ' -f1,3,4)"
echo ""

# メモリ関連の設定
echo "6. Memory settings:"
echo "==================="
echo "ulimit -c: $(ulimit -c)"
echo "ulimit -v: $(ulimit -v)"
echo ""

echo "=== Analysis complete ==="
