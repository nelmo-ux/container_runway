# Container Runway - Quick Start Guide

## 前提条件

- Linux (x86_64)
- Docker 20.10以降
- Go 1.21以降 (shimビルド用)
- root権限

## インストール手順

### 1. ランタイムとshimをビルド

```bash
# ランタイムビルド
cd /home/nelmo/runner
make clean && make

# shimビルド
cd shim
export PATH=/home/nelmo/runner/go/bin:$PATH
go build -o containerd-shim-runway-v2
cd ..
```

### 2. インストール

```bash
# 自動インストールスクリプトを使用
sudo ./INSTALL.sh
```

**または手動インストール:**

```bash
# ランタイムをインストール
sudo cp runtime /usr/local/bin/
sudo chmod +x /usr/local/bin/runtime

# shimをインストール
sudo cp shim/containerd-shim-runway-v2 /usr/local/bin/
sudo chmod +x /usr/local/bin/containerd-shim-runway-v2

# 状態ディレクトリ作成
sudo mkdir -p /run/runway
sudo chmod 755 /run/runway

# 動作確認
runtime --version
runtime features
```

### 3. Docker設定

```bash
# 自動設定スクリプトを使用
sudo ./configure-docker.sh
```

**または手動設定:**

```bash
# daemon.jsonを編集
sudo tee /etc/docker/daemon.json <<EOF
{
  "runtimes": {
    "runway": {
      "path": "/usr/local/bin/runtime",
      "runtimeArgs": ["--root", "/run/runway"]
    }
  }
}
EOF

# Docker再起動
sudo systemctl restart docker

# 確認
docker info | grep -A 5 "Runtimes:"
```

## 動作確認

### busyboxで基本テスト

```bash
# 簡単な実行
docker run --runtime=runway busybox echo "Hello from Runway!"

# より詳細なテスト
docker run --runtime=runway busybox sh -c "
  echo '=== Container Info ===';
  uname -a;
  echo '';
  echo '=== Available Commands ===';
  ls /bin | head -10;
  echo '';
  echo '=== Process Info ===';
  ps aux;
"
```

### Alpineで対話的テスト

```bash
docker run -it --runtime=runway alpine sh
```

## トラブルシューティング

### エラー: "runtime not found"

```bash
# パスを確認
which runtime
ls -l /usr/local/bin/runtime

# 再インストール
sudo ./INSTALL.sh
```

### エラー: "runtime not registered in Docker"

```bash
# Docker設定を確認
cat /etc/docker/daemon.json

# Docker再起動
sudo systemctl restart docker
docker info | grep runway
```

### エラー: "permission denied"

```bash
# 状態ディレクトリの権限確認
ls -ld /run/runway
sudo chmod 755 /run/runway

# バイナリの権限確認
ls -l /usr/local/bin/runtime
ls -l /usr/local/bin/containerd-shim-runway-v2
```

### エラー: "shim not found"

```bash
# shimの存在確認
ls -l /usr/local/bin/containerd-shim-runway-v2

# 再ビルド＆インストール
cd shim
export PATH=/home/nelmo/runner/go/bin:$PATH
go build -o containerd-shim-runway-v2
sudo cp containerd-shim-runway-v2 /usr/local/bin/
```

### Dockerログの確認

```bash
# Dockerデーモンログ
sudo journalctl -u docker -n 50 --no-pager

# コンテナログ
sudo journalctl -xe | grep runway
```

## ランタイム単体での使用

Dockerを使わずに直接ランタイムを使用する場合:

```bash
# バンドル準備
mkdir -p /tmp/test-bundle/rootfs
# (rootfsを配置)

# config.json作成
cat > /tmp/test-bundle/config.json <<'EOF'
{
  "ociVersion": "1.0.0",
  "root": {"path": "rootfs"},
  "process": {
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/sh"],
    "env": ["PATH=/bin"],
    "cwd": "/"
  },
  "hostname": "test",
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "uts"},
      {"type": "mount"}
    ]
  }
}
EOF

# 実行
sudo runtime run --bundle /tmp/test-bundle test-container
```

## 次のステップ

- [README.md](README.md) - プロジェクト概要
- [PROBLEM.md](PROBLEM.md) - 既知の制限事項
- [NEXT_STEPS.md](NEXT_STEPS.md) - 今後の実装予定

## サポート

問題が発生した場合は、以下を確認してください:

1. `runtime --version` と `runtime features` の出力
2. `/etc/docker/daemon.json` の内容
3. `docker info` の出力
4. Dockerデーモンのログ (`journalctl -u docker`)
5. `/run/runway` ディレクトリの権限
