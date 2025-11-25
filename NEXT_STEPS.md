# 次の作業に役立つガイド

このメモは、OCI 準拠テストの実施や追加検証を行う際に役立つ手順とヒントをまとめたものです。

## 1. 事前準備
- **ソース取得**: `runtime-tools/` ディレクトリが最新であることを確認。
- **バイナリビルド**:
  ```bash
  cd runtime-tools
  make runtimetest validation-executables
  ```
- **Node.js 依存**: TAP ランナーが不足している場合は次を実行。
  ```bash
  cd runtime-tools
  npm install tap
  ```

## 2. ルートディレクトリ (`--root`) の扱い
- ランタイムはデフォルトで以下を使用します。
  - `root` 権限時: `/run/mruntime`
  - 非特権時: `XDG_RUNTIME_DIR/mruntime` または `/tmp/mruntime-<uid>`
- 既定が使えない場合は、適宜 `--root` を指定してください。

## 3. OCI 検証スイートの実行
1. **root 権限での実行**が推奨（ユーザー名前空間・cgroup 設定が必要なため）。
2. TAP ランナーを指定してテストを走らせます。
   ```bash
   cd runtime-tools
   sudo make TAPTOOL='prove -Q -j4' RUNTIME=/path/to/runtime localvalidation
   ```
3. 特定テストのみを確認したい場合:
   ```bash
   sudo make TAPTOOL='prove -Q -j4' \
        RUNTIME=/path/to/runtime \
        VALIDATION_TESTS=validation/state/state.t \
        localvalidation
   ```
4. 失敗時は `validation/<name>/*.t` を直接実行し、詳細な YAML ダンプを確認:
   ```bash
   cd runtime-tools
   sudo RUNTIME=/path/to/runtime validation/state/state.t
   ```

## 4. よくあるエラーと対処
- **`Operation not permitted`**: rootless では `clone(CLONE_NEWUSER)` や `pivot_root` が拒否されることがあります。root 権限または適切な namespace 権限を付与してください。
- **`Failed to create runtime root directory`**: `--root` で明示した先が書き込み不可。再設定が必要です。
- **TAP ランナーが ELF として解釈される**: `tap` ではなく `prove` を使う、または `node_modules/.bin/tap` を直接指定することで解消できます。

## 5. 個別機能の手動検証
- **ランタイム動作テスト**:
  ```bash
  cd runtime-tools
  bundle_dir=$(mktemp -d)
  tar -xf rootfs-amd64.tar.gz -C "$bundle_dir"
  oci-runtime-tool generate --output "$bundle_dir/config.json"
  sudo /path/to/runtime run --bundle "$bundle_dir" sample-container
  ```
  - 終了後は `runway.version` などのアノテーションを `state` コマンドで確認。
- **マウント/マスキング**: `config.json` の `mounts`/`maskedPaths` を編集し、期待通りのバインド・マスクが行われているかシェルで確認。
- **UID/GID マッピング**: `linux.uidMappings` を設定し、コンテナ内の `id` コマンドで確認。

## 6. 追加改善のヒント
- `--console-socket` や `exec` など未対応項目を実装する場合は、`validation/hooks_stdin` や `process/*.t` 系テストを個別に使用。
- セキュリティ関連（seccomp/AppArmor など）は `validation/linux_seccomp` や `linux_process_apparmor_profile` のテスト構造を参照。

## 7. 片付け
- テスト終了後は作成したバンドルや `/tmp/mruntime-*` ディレクトリを削除。
- ルート実行時に `/run/mruntime/<id>` が残っている場合は `delete` コマンドでクリーンアップ。

---
このファイルは今後のタスクで参照しやすいよう、必要に応じて更新してください。
