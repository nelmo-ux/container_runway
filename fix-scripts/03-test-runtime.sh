#!/bin/bash
# ステップ3: ランタイムのテスト

set -e

echo "=== Testing Runway Runtime ==="
echo ""

# テスト1: バージョン確認
echo "Test 1: Version check"
/usr/local/bin/runtime --version
echo "✓ Passed"
echo ""

# テスト2: features確認
echo "Test 2: Features check"
/usr/local/bin/runtime features | head -20
echo "✓ Passed"
echo ""

# テスト3: Dockerでの実行
echo "Test 3: Docker execution with runway runtime"
echo "Running: docker run --rm --runtime=runway busybox echo 'Hello from Runway!'"
echo ""

# エラー出力を詳細に記録
if docker run --rm --runtime=runway busybox echo "Hello from Runway!" 2>&1 | tee /tmp/runway-test.log; then
    echo ""
    echo "✓ Docker test PASSED!"
    exit 0
else
    EXIT_CODE=$?
    echo ""
    echo "✗ Docker test FAILED (exit code: $EXIT_CODE)"
    echo ""
    echo "=== Debugging information ==="
    echo ""
    echo "Recent kernel messages:"
    dmesg | tail -10 | grep -i "runtime\|segfault\|general protection" || echo "(no relevant messages)"
    echo ""
    echo "Check for core dumps:"
    ls -lh /tmp/core-runtime-* 2>/dev/null || echo "(no core dumps found)"
    echo ""
    echo "Full error log saved to: /tmp/runway-test.log"
    exit $EXIT_CODE
fi
