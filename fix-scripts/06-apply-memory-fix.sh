#!/bin/bash
# メモリ問題の修正を適用

set -e

cd /home/nelmo/runner

echo "=== Applying Memory Management Fix ==="
echo ""

# バックアップ作成
if [ ! -d "backup-"* ]; then
    echo "Creating backup..."
    ./fix-scripts/05-backup-code.sh
else
    echo "Backup already exists, skipping..."
fi

echo ""
echo "=== Manual fix required for main.cpp ==="
echo ""
echo "The issue is at main.cpp:638-710"
echo ""
echo "Problem:"
echo "  - args.release() is called BEFORE fork()"
echo "  - This causes memory corruption in libstdc++ when both parent and child"
echo "    try to access the same std::vector/std::string internals"
echo ""
echo "Solution:"
echo "  - Move args.release() AFTER fork(), inside the child process block"
echo "  - Let the parent process keep the unique_ptr so it auto-cleans"
echo "  - fork() creates a proper copy of memory for the child"
echo ""
echo "Apply these changes to main.cpp:"
echo ""
echo "1. Remove line 638-640:"
echo "   // Release unique_ptr ownership BEFORE fork to avoid double-free"
echo "   // After this, both parent and child will use raw pointer"
echo "   ContainerArgs* args_ptr = args.release();"
echo ""
echo "2. Move args.release() to line 655 (inside 'if (pid == 0)' block):"
echo "   if (pid == 0) {"
echo "       // Child process: setup namespaces then run container_main logic"
echo "       ContainerArgs* args_ptr = args.release();"
echo ""
echo "3. Update comment at line 709-710:"
echo "   // Parent process: continue setup"
echo "   // args unique_ptr is still valid and will auto-cleanup"
echo ""
echo "4. Close namespace FDs in parent at line 712:"
echo "   for (auto& ns_fd : args->join_namespaces) {"
echo "       close(ns_fd.first);"
echo "   }"
echo ""
echo "After making these changes, rebuild and test:"
echo "  cd /home/nelmo/runner/fix-scripts"
echo "  ./00-stop-docker.sh"
echo "  ./01-rebuild-debug.sh"
echo "  ./03-test-runtime.sh"
