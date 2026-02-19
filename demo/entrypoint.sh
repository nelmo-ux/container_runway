#!/bin/sh
set -e

echo "=== Runway Seccomp Demo ==="
echo ""

echo "[1] uname -a"
uname -a
echo ""

echo "[2] id"
id
echo ""

echo "[3] ls /"
ls /
echo ""

echo "[4] cat /etc/os-release"
cat /etc/os-release
echo ""

echo "[5] getpid (via /proc/self/status)"
head -n 6 /proc/self/status
echo ""

echo "=== All checks passed ==="
