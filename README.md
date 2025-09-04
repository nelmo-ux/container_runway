# Container Runway - Linuxコンテナランタイム

## 概要
Container Runwayは、OCI (Open Container Initiative) 仕様に準拠した軽量なLinuxコンテナランタイムです。Linux名前空間とchrootを利用して、プロセスの分離環境を提供します。

## 主な機能
- **OCI準拠**: OCI Runtime Specificationに基づいた`config.json`の読み込みと解析
- **名前空間の分離**: PID、UTS、IPC、ネットワーク、マウント、ユーザー、cgroupの名前空間をサポート
- **ファイルシステムの分離**: chrootによるルートファイルシステムの分離
- **読み取り専用ルートファイルシステム**: オプションでルートファイルシステムを読み取り専用にマウント
- **状態管理**: コンテナの状態をJSON形式で保存・管理
- **同期メカニズム**: 名前付きパイプ(FIFO)を使用したプロセス間同期

## 技術スタック
- **言語**: C++11
- **JSONライブラリ**: nlohmann/json (json.hpp)
- **ビルドシステム**: Make / CMake
- **システムコール**: Linux名前空間API、mount、chroot

## プロジェクト構成
```
container-runway/
├── main.cpp              # メインソースコード（コンテナランタイムの実装）
├── json.hpp              # JSONパーサライブラリ（nlohmann/json）
├── Makefile              # ビルド設定ファイル
├── CMakeLists.txt        # CMakeビルド設定
├── runtime               # ビルド済み実行ファイル
├── cmake-build-debug/    # CMakeビルドディレクトリ
├── .idea/                # IDE設定ファイル
├── .git/                 # Gitリポジトリ
└── .gitignore            # Git除外設定
```

## コンテナ作成の流れ
1. **config.json解析**: OCIランタイム仕様のconfig.jsonファイルを読み込み
2. **名前空間の準備**: 指定された名前空間（PID、UTS、IPC等）を設定
3. **同期用FIFO作成**: プロセス間通信用の名前付きパイプを作成
4. **子プロセスのclone**: 新しい名前空間で子プロセスを生成
5. **環境設定**: ホスト名設定、chrootによるルートファイルシステムの変更
6. **procマウント**: /procファイルシステムのマウント
7. **コマンド実行**: config.jsonで指定されたプロセスをexecvpで実行

## ビルド方法

### Makeを使用する場合
```bash
# ビルド
make

# インストール（管理者権限が必要）
sudo make install

# アンインストール
sudo make uninstall

# クリーン
make clean

# ヘルプの表示
make help
```

### CMakeを使用する場合
```bash
mkdir build
cd build
cmake ..
make
```

## 使用方法

### 基本的な使い方
```bash
# コンテナの作成
sudo ./runtime create <container-id> <bundle-path>

# コンテナの開始
sudo ./runtime start <container-id>

# コンテナの状態確認
sudo ./runtime state <container-id>

# コンテナの削除
sudo ./runtime delete <container-id>
```

### config.jsonの例
```json
{
  "ociVersion": "1.0.0",
  "root": {
    "path": "rootfs",
    "readonly": false
  },
  "process": {
    "terminal": false,
    "args": ["/bin/sh"],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/"
  },
  "hostname": "container",
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "uts"},
      {"type": "ipc"},
      {"type": "net"},
      {"type": "mnt"}
    ]
  }
}
```

## データ構造

### ContainerState
コンテナの状態を管理する構造体：
- `id`: コンテナID
- `pid`: プロセスID
- `status`: 状態（creating、created、running、stopped）
- `bundle_path`: バンドルパス

### OCIConfig
OCI仕様のconfig.jsonに対応する構造体：
- `ociVersion`: OCIバージョン
- `root`: ルートファイルシステム設定
- `process`: プロセス設定
- `hostname`: ホスト名
- `linux`: Linux固有の設定（名前空間等）

## 状態管理
コンテナの状態は`/run/runtime/<container-id>/state.json`に保存されます。

## セキュリティ考慮事項
- ルート権限が必要（名前空間操作とchrootのため）
- 読み取り専用ルートファイルシステムオプションをサポート
- 適切な権限管理が必要

## 今後の改善点
- エラーハンドリングの強化
- リソース制限（cgroups）の実装
- ネットワーク設定の詳細化
- ログ機能の追加
- テストスイートの作成

## 開発者向け情報
- C++11標準を使用
- nlohmann/jsonライブラリでJSONの処理を簡潔に実装
- Linux固有のシステムコールを多用するため、Linux環境でのみ動作
- x86もしくはAMD64でのみ動作(ARM未対応)
## 参考資料
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [nlohmann/json](https://github.com/nlohmann/json)