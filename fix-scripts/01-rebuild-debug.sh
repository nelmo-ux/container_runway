#!/bin/bash
# ステップ1: デバッグビルドの作成とインストール

set -e

cd /home/nelmo/runner

echo "=== Step 1: Clean previous build ==="
make clean

echo ""
echo "=== Step 2: Build with debug symbols (no optimization) ==="
make CXXFLAGS="-std=c++11 -Wall -O0 -g -Iinclude -I. -fno-omit-frame-pointer"

echo ""
echo "=== Step 3: Verify binary ==="
file ./runtime
ldd ./runtime

echo ""
echo "=== Step 4: Check version ==="
./runtime --version

echo ""
echo "=== Step 5: Check if binary is in use ==="
if lsof /usr/local/bin/runtime 2>/dev/null; then
    echo "ERROR: /usr/local/bin/runtime is currently in use"
    echo "Please run ./00-stop-docker.sh first"
    exit 1
fi

echo ""
echo "=== Step 6: Install (requires sudo) ==="
sudo cp ./runtime /usr/local/bin/runtime
sudo chmod +x /usr/local/bin/runtime

echo ""
echo "=== Step 7: Verify installation ==="
which runtime
/usr/local/bin/runtime --version

echo ""
echo "=== Step 8: Restart Docker ==="
sudo systemctl start docker || sudo service docker start
sleep 3

# Dockerが起動するまで待機
echo "Waiting for Docker to be ready..."
for i in {1..10}; do
    if docker info >/dev/null 2>&1; then
        echo "✓ Docker is ready"
        break
    fi
    echo "Waiting... ($i/10)"
    sleep 2
done

echo ""
echo "=== Debug build installed successfully ==="
echo "You can now test with: docker run --rm --runtime=runway busybox echo 'test'"
