#!/bin/bash
# ステップ5: コードのバックアップ作成

set -e

cd /home/nelmo/runner

BACKUP_DIR="backup-$(date +%Y%m%d-%H%M%S)"

echo "=== Creating Code Backup ==="
echo ""
echo "Backup directory: $BACKUP_DIR"

mkdir -p "$BACKUP_DIR"
cp main.cpp "$BACKUP_DIR/"
cp src/runtime/isolation.cpp "$BACKUP_DIR/"

echo "✓ Backed up main.cpp"
echo "✓ Backed up src/runtime/isolation.cpp"
echo ""
echo "=== Backup created successfully ==="
echo "Location: /home/nelmo/runner/$BACKUP_DIR"
