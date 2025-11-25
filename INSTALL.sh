#!/bin/bash
# Container Runway - Installation Script

set -e

echo "=== Container Runway Installation ==="
echo ""

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

RUNTIME_SRC="/home/nelmo/runner/runtime"
SHIM_SRC="/home/nelmo/runner/shim/containerd-shim-runway-v2"
INSTALL_DIR="/usr/local/bin"

echo "Step 1: Installing runtime binary..."
if [ ! -f "$RUNTIME_SRC" ]; then
    echo "Error: Runtime binary not found at $RUNTIME_SRC"
    echo "Please run 'make' first to build the runtime"
    exit 1
fi

cp "$RUNTIME_SRC" "$INSTALL_DIR/runtime"
chmod +x "$INSTALL_DIR/runtime"
echo "  ✓ Runtime installed to $INSTALL_DIR/runtime"

echo ""
echo "Step 2: Installing containerd shim..."
if [ ! -f "$SHIM_SRC" ]; then
    echo "Error: Shim binary not found at $SHIM_SRC"
    echo "Please build the shim first (cd shim && go build)"
    exit 1
fi

cp "$SHIM_SRC" "$INSTALL_DIR/containerd-shim-runway-v2"
chmod +x "$INSTALL_DIR/containerd-shim-runway-v2"
echo "  ✓ Shim installed to $INSTALL_DIR/containerd-shim-runway-v2"

echo ""
echo "Step 3: Creating runtime state directory..."
mkdir -p /run/runway
chmod 755 /run/runway
echo "  ✓ State directory created at /run/runway"

echo ""
echo "Step 4: Verifying installation..."
"$INSTALL_DIR/runtime" --version
if [ $? -eq 0 ]; then
    echo "  ✓ Runtime verification successful"
else
    echo "  ✗ Runtime verification failed"
    exit 1
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Configure Docker to use runway runtime:"
echo "     sudo ./configure-docker.sh"
echo "  2. Test with busybox:"
echo "     docker run --runtime=runway busybox echo 'Hello!'"
echo ""
