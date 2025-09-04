#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <system_error>

#include "json.hpp"

// nlohmann::jsonを使いやすくするためのエイリアス
using json = nlohmann::json;

constexpr int STACK_SIZE = 1024 * 1024; // 1MB

// 状態ファイルを保存するベースディレクトリ
const std::string STATE_BASE_PATH = "/run/runtime/";

// --- config.jsonの構造に対応するC++構造体 ---

struct ProcessConfig {
    bool terminal;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd;
};

struct RootConfig {
    std::string path;
    bool readonly;
};

struct LinuxNamespaceConfig {
    std::string type;
    std::string path;
};

struct LinuxConfig {
    std::vector<LinuxNamespaceConfig> namespaces;
};

// config.json全体を表す構造体
struct OCIConfig {
    std::string ociVersion;
    RootConfig root;
    ProcessConfig process;
    std::string hostname;
    LinuxConfig linux;
};

// --- JSONからのデシリアライズ関数 ---

// from_json/to_jsonをnlohmann/jsonにアタッチすることで自動的に変換できる?(とりあえずできてそう)
void from_json(const json& j, ProcessConfig& p) {
    j.at("args").get_to(p.args);
    j.at("cwd").get_to(p.cwd);
    if (j.contains("terminal")) {
        j.at("terminal").get_to(p.terminal);
    } else {
        p.terminal = false;
    }
    if (j.contains("env")) {
        j.at("env").get_to(p.env);
    }
}

void from_json(const json& j, RootConfig& r) {
    j.at("path").get_to(r.path);
    if (j.contains("readonly")) {
        j.at("readonly").get_to(r.readonly);
    } else {
        r.readonly = false;
    }
}

void from_json(const json& j, LinuxNamespaceConfig& ns) {
    j.at("type").get_to(ns.type);
    if (j.contains("path")) {
        j.at("path").get_to(ns.path);
    }
}

void from_json(const json& j, LinuxConfig& l) {
    if (j.contains("namespaces")) {
        j.at("namespaces").get_to(l.namespaces);
    }
}

void from_json(const json& j, OCIConfig& c) {
    j.at("ociVersion").get_to(c.ociVersion);
    j.at("root").get_to(c.root);
    j.at("process").get_to(c.process);
    if (j.contains("hostname")) {
        j.at("hostname").get_to(c.hostname);
    }
    if (j.contains("linux")) {
        j.at("linux").get_to(c.linux);
    }
}

// config.jsonを読み込んでパースする関数
OCIConfig load_config(const std::string& bundle_path) {
    std::string config_path = bundle_path + "./config.json";
    std::ifstream ifs(config_path);
    if (!ifs) {
        throw std::runtime_error("config.jsonの読み込みに失敗: " + config_path);
    }
    json j;
    ifs >> j;
    return j.get<OCIConfig>();
}

// 名前付きパイプ（FIFO）のパスを生成するヘルパー関数
std::string get_fifo_path(const std::string& container_id) {
    return STATE_BASE_PATH + container_id + "/sync_fifo";
}

// コンテナに渡す引数を格納する構造体
struct ContainerArgs {
    char** argv;
    std::string sync_fifo_path;
    std::string rootfs_path;
    std::string hostname;
    bool rootfs_readonly;
};

// コンテナの状態を表す構造体
struct ContainerState {
    std::string id;
    pid_t pid = -1;
    std::string status; // creating, created, running, stopped
    std::string bundle_path;

    // 状態をJSON文字列にシリアライズ
    std::string to_json() const {
        json j = {
                {"id", id},
                {"pid", pid},
                {"status", status},
                {"bundle_path", bundle_path}
        };
        return j.dump(4); // 4スペースでインデント
    }

    // JSON文字列からデシリアライズ
    static ContainerState from_json(const std::string& json_str) {
        ContainerState state;
        json j = json::parse(json_str);
        j.at("id").get_to(state.id);
        j.at("pid").get_to(state.pid);
        j.at("status").get_to(state.status);
        j.at("bundle_path").get_to(state.bundle_path);
        return state;
    }
};

// 状態をファイルに保存/読み込みするヘルパー関数
bool save_state(const ContainerState& state) {
    std::string container_path = STATE_BASE_PATH + state.id;
    std::string state_file_path = container_path + "/state.json";
    if (mkdir(container_path.c_str(), 0755) != 0 && errno != EEXIST) {
        perror("状態ディレクトリの作成に失敗");
        return false;
    }
    std::ofstream ofs(state_file_path);
    if (!ofs) {
        std::cerr << "状態ファイルのオープンに失敗: " << state_file_path << std::endl;
        return false;
    }
    ofs << state.to_json();
    return true;
}

ContainerState load_state(const std::string& container_id) {
    std::string state_file_path = STATE_BASE_PATH + container_id + "/state.json";
    std::ifstream ifs(state_file_path);
    if (!ifs) {
        throw std::runtime_error("状態ファイルの読み込みに失敗: " + state_file_path);
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return ContainerState::from_json(buffer.str());
}

// 子プロセス（コンテナ）のエントリーポイント
int container_main(void* arg) {
    ContainerArgs* args = static_cast<ContainerArgs*>(arg);

    // 1. 開始合図を待つ
    char buf;
    int fifo_fd = open(args->sync_fifo_path.c_str(), O_RDONLY);
    if (fifo_fd == -1) {
        perror("FIFOのオープンに失敗(read)"); //PID異常ハンドリング
        return 1;
    }
    if (read(fifo_fd, &buf, 1) <= 0) {
        close(fifo_fd);
        return 1;
    }
    close(fifo_fd);

    // 2. 環境設定
    if (sethostname(args->hostname.c_str(), args->hostname.length()) != 0) {
        perror("sethostnameに失敗"); return 1;
    }
    // chrootの前にカレントディレクトリを移動
    if (chdir(args->rootfs_path.c_str()) != 0) {
        perror("rootfsへのchdirに失敗"); return 1;
    }
    if (chroot(".") != 0) {
        perror("chrootに失敗"); return 1;
    }
    if (chdir("/") != 0) {
        perror("ルートへのchdirに失敗"); return 1;
    }
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("procのマウントに失敗");
    }
    // rootfsをreadonlyにする場合
    if (args->rootfs_readonly) {
        if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL) != 0) {
            perror("rootfsの再マウント(readonly)に失敗");
        }
    }

    // 3. 指定されたコマンドの実行
    if (execvp(args->argv[0], args->argv)) {
        perror("execvpに失敗");
    }

    return 1; // execvpが失敗した場合のみ Todo: エラーハンドリング追加
}

// OCI `create` コマンド
void create_container(const std::string& id, const std::string& bundle_path) {
    OCIConfig config;
    try {
        config = load_config(bundle_path);
    } catch (const std::exception& e) {
        std::cerr << "設定ファイルの処理中にエラーが発生: " << e.what() << std::endl;
        return;
    }

    std::string container_dir = STATE_BASE_PATH + id;
    if (mkdir(container_dir.c_str(), 0755) != 0 && errno != EEXIST) {
        perror("コンテナディレクトリの作成に失敗"); return;
    }

    std::string fifo_path = get_fifo_path(id);
    if (mkfifo(fifo_path.c_str(), 0666) == -1 && errno != EEXIST) {
        perror("mkfifoに失敗"); return;
    }

    // config.jsonから読み込んだ値でContainerArgsを準備
    ContainerArgs args;
    args.sync_fifo_path = fifo_path;
    args.rootfs_path = bundle_path + "/" + config.root.path;
    args.hostname = config.hostname;
    args.rootfs_readonly = config.root.readonly;

    // execvpのためにコマンド引数をchar*の配列に変換
    std::vector<char*> argv_vec;
    for (const auto& arg_str : config.process.args) {
        argv_vec.push_back(const_cast<char*>(arg_str.c_str()));
    }
    argv_vec.push_back(nullptr); // 配列の終端
    args.argv = argv_vec.data();

    // config.jsonから読み込んだ名前空間でcloneフラグを設定
    int flags = SIGCHLD;
    std::map<std::string, int> ns_map = {
            {"pid", CLONE_NEWPID},
            {"uts", CLONE_NEWUTS},
            {"ipc", CLONE_NEWIPC},
            {"net", CLONE_NEWNET},
            {"mnt", CLONE_NEWNS},
            {"user", CLONE_NEWUSER},
            {"cgroup", CLONE_NEWCGROUP}
    };
    for (const auto& ns : config.linux.namespaces) {
        if (ns_map.count(ns.type)) {
            flags |= ns_map[ns.type];
        }
    }

    char* stack = new char[STACK_SIZE];
    char* stack_top = stack + STACK_SIZE;

    pid_t pid = clone(container_main, stack_top, flags, &args);

    if (pid == -1) {
        perror("cloneに失敗");
        delete[] stack;
        unlink(fifo_path.c_str());
        return;
    }

    ContainerState state;
    state.id = id;
    state.pid = pid;
    state.status = "created";
    state.bundle_path = bundle_path;

    if (!save_state(state)) {
        std::cerr << "状態の保存に失敗しました。" << std::endl;
        kill(pid, SIGKILL);
    } else {
        std::cout << "コンテナ '" << id << "' を作成しました。状態: created, PID: " << pid << std::endl;
    }
}

// OCI `start` コマンド
void start_container(const std::string& id, bool attach) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    if (state.status != "created") {
        std::cerr << "エラー: コンテナは 'created' 状態ではありません (現在: " << state.status << ")" << std::endl;
        return;
    }

    std::string fifo_path = get_fifo_path(id);
    int fifo_fd = open(fifo_path.c_str(), O_WRONLY);
    if (fifo_fd == -1) {
        perror("FIFOのオープンに失敗(write)");
        return;
    }

    if (write(fifo_fd, "1", 1) != 1) {
        perror("FIFOへの書き込みに失敗");
        close(fifo_fd);
        return;
    }
    close(fifo_fd);

    state.status = "running";
    save_state(state);
    std::cout << "コンテナ '" << id << "' を開始しました。" << std::endl;

    if (attach) {
        std::cout << "コンテナにアタッチします。終了するには 'exit' を入力するか、Ctrl+Dを押してください。" << std::endl;
        int status;
        waitpid(state.pid, &status, 0);

        std::cout << "コンテナ '" << id << "' が終了しました。" << std::endl;
        state.status = "stopped";
        save_state(state);
    }
}

// OCI `state` コマンド
void show_state(const std::string& id) {
    try {
        ContainerState state = load_state(id);
        if (state.pid != -1 && kill(state.pid, 0) != 0 && errno == ESRCH) {
            if (state.status != "stopped") {
                state.status = "stopped";
                save_state(state);
            }
        }
        std::cout << state.to_json() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

// OCI `kill` コマンド
void kill_container(const std::string& id, int signal) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    if (state.status != "running" && state.status != "created") {
        std::cerr << "エラー: コンテナは実行中または作成済みではありません。" << std::endl;
        return;
    }

    if (kill(state.pid, signal) == 0) {
        std::cout << "シグナル " << signal << " をプロセス " << state.pid << " に送信しました。" << std::endl;
        if (signal == SIGKILL || signal == SIGTERM) {
            waitpid(state.pid, NULL, 0);
            state.status = "stopped";
            save_state(state);
            std::cout << "コンテナ '" << id << "' は停止しました。" << std::endl;
        }
    } else {
        perror("killに失敗");
    }
}

// OCI `delete` コマンド
void delete_container(const std::string& id) {
    ContainerState state;
    try {
        state = load_state(id);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl; return;
    }

    if (state.status != "stopped") {
        if (state.pid != -1 && kill(state.pid, 0) == 0) {
            std::cerr << "エラー: コンテナはまだ実行中です。先に kill してください。" << std::endl;
            return;
        }
        state.status = "stopped";
        save_state(state);
    }

    std::string container_path = STATE_BASE_PATH + id;
    std::string state_file = container_path + "/state.json";
    std::string fifo_file = get_fifo_path(id);

    unlink(fifo_file.c_str());
    if (remove(state_file.c_str()) != 0) {
        // エラーでも処理を続行
        perror("状態ファイルの削除に失敗");
    }
    if (rmdir(container_path.c_str()) != 0) {
        perror("状態ディレクトリの削除に失敗");
    }
    std::cout << "コンテナ '" << id << "' を削除しました。" << std::endl;
}

void print_usage(const char* prog) {
    std::cerr << "使い方: " << prog << " <command> [args...]\n"
              << "\n"
              << "コマンド:\n"
              << "  create <id> <bundle-path>      コンテナを作成する\n"
              << "  start  [-a|--attach] <id>      作成されたコンテナを開始する\n"
              << "                                 -a, --attach: コンテナにアタッチし対話的に操作する\n"
              << "  state  <id>                    コンテナの状態を表示する\n"
              << "  kill   <id> [signal]           コンテナにシグナルを送る (デフォルト: SIGTERM)\n"
              << "  delete <id>                    停止したコンテナを削除する\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (getuid() != 0) {
        std::cerr << "エラー: このプログラムはroot権限で実行する必要があります。" << std::endl;
        return 1;
    }

    mkdir(STATE_BASE_PATH.c_str(), 0755);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "create") {
        if (argc != 4) { print_usage(argv[0]); return 1; }
        create_container(argv[2], argv[3]);
    } else if (command == "start") {
        bool attach = false;
        std::string id;
        if (argc == 3) {
            id = argv[2];
        } else if (argc == 4) {
            std::string flag = argv[2];
            if (flag == "-a" || flag == "--attach") {
                attach = true;
                id = argv[3];
            } else {
                print_usage(argv[0]); return 1;
            }
        } else {
            print_usage(argv[0]); return 1;
        }
        start_container(id, attach);
    } else if (command == "state") {
        if (argc != 3) { print_usage(argv[0]); return 1; }
        show_state(argv[2]);
    } else if (command == "kill") {
        if (argc < 3 || argc > 4) { print_usage(argv[0]); return 1; }
        int sig = (argc == 4) ? std::stoi(argv[3]) : SIGTERM;
        kill_container(argv[2], sig);
    } else if (command == "delete") {
        if (argc != 3) { print_usage(argv[0]); return 1; }
        delete_container(argv[2]);
    } else {
        std::cerr << "エラー: 不明なコマンド '" << command << "'" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
