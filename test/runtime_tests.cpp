#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#define main runtime_cli_main
#include "../main.cpp"
#undef main

struct TestContext {
    int passed = 0;
    int failed = 0;

    void expect(bool condition, const std::string& name, const std::string& message = "") {
        if (condition) {
            ++passed;
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name;
            if (!message.empty()) {
                std::cerr << " - " << message;
            }
            std::cerr << std::endl;
        }
    }
};

std::string path_join(const std::string& base, const std::string& child) {
    if (base.empty()) {
        return child;
    }
    if (child.empty()) {
        return base;
    }
    if (base == "/") {
        return "/" + child;
    }
    if (base.back() == '/') {
        return base + child;
    }
    return base + "/" + child;
}

std::string make_temp_dir(const std::string& prefix) {
    std::string tmpl = "/tmp/" + prefix + "XXXXXX";
    std::vector<char> buffer(tmpl.begin(), tmpl.end());
    buffer.push_back('\0');
    char* created = mkdtemp(buffer.data());
    if (!created) {
        throw std::runtime_error("mkdtemp failed");
    }
    return created;
}

void remove_tree(const std::string& path) {
    if (path.empty()) {
        return;
    }
    struct stat st {};
    if (lstat(path.c_str(), &st) != 0) {
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR* dir = opendir(path.c_str());
        if (!dir) {
            rmdir(path.c_str());
            return;
        }
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            remove_tree(path_join(path, entry->d_name));
        }
        closedir(dir);
        rmdir(path.c_str());
    } else {
        unlink(path.c_str());
    }
}

void write_file(const std::string& path, const std::string& contents) {
    ensure_parent_directory(path);
    std::ofstream ofs(path);
    ofs << contents;
}

std::string read_file(const std::string& path) {
    std::ifstream ifs(path);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}

std::string test_state_root() {
    std::string root = make_temp_dir("runway-state-");
    g_global_options.root_path = root;
    return root;
}

void cleanup_state_root(const std::string& root) {
    remove_tree(root);
}

void test_iso8601_format(TestContext& ctx) {
    const std::string ts = iso8601_now();
    bool has_z = !ts.empty() && ts.back() == 'Z';
    ctx.expect(has_z, "iso8601_now terminator", ts);
    bool has_fraction = ts.find('.') != std::string::npos;
    ctx.expect(has_fraction, "iso8601_now fractional", ts);
}

void test_collect_process_tree(TestContext& ctx) {
    pid_t self = getpid();
    auto pids = collect_process_tree(self);
    bool contains_self = std::find(pids.begin(), pids.end(), self) != pids.end();
    ctx.expect(contains_self, "collect_process_tree contains self");
}

void test_wait_for_process(TestContext& ctx) {
    int status = 0;
    pid_t child = fork();
    if (child == 0) {
        _exit(0);
    }
    bool immediate = wait_for_process(child, 0, status);
    ctx.expect(immediate && WIFEXITED(status), "wait_for_process immediate success");

    pid_t slow_child = fork();
    if (slow_child == 0) {
        sleep(5);
        _exit(42);
    }
    int slow_status = 0;
    bool completed = wait_for_process(slow_child, 1, slow_status);
    ctx.expect(!completed, "wait_for_process timeout triggers kill");
}

void test_parse_create_options(TestContext& ctx) {
    CreateOptions options;
    std::vector<std::string> args = {
            "runtime", "--bundle", "/tmp/bundle", "--pid-file", "/tmp/pid",
            "--console-socket", "/tmp/console.sock", "--no-pivot", "--notify-socket",
            "notify.sock", "--preserve-fds", "2", "demo"
    };
    std::vector<char*> argv;
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    bool ok = parse_create_options(static_cast<int>(args.size()), argv.data(), options);
    ctx.expect(ok, "parse_create_options success");
    if (ok) {
        ctx.expect(options.bundle == "/tmp/bundle", "parse_create_options bundle", options.bundle);
        ctx.expect(options.pid_file == "/tmp/pid", "parse_create_options pid file", options.pid_file);
        ctx.expect(options.console_socket == "/tmp/console.sock", "parse_create_options console socket", options.console_socket);
        ctx.expect(options.no_pivot, "parse_create_options no_pivot flag");
        ctx.expect(options.notify_socket == "notify.sock", "parse_create_options notify", options.notify_socket);
        ctx.expect(options.preserve_fds == 2, "parse_create_options preserve fds", std::to_string(options.preserve_fds));
        ctx.expect(options.id == "demo", "parse_create_options id", options.id);
    }

    std::vector<std::string> missing = {"runtime", "--bundle", "/tmp"};
    std::vector<char*> missing_argv;
    for (auto& arg : missing) {
        missing_argv.push_back(const_cast<char*>(arg.c_str()));
    }
    bool missing_ok = parse_create_options(static_cast<int>(missing.size()), missing_argv.data(), options);
    ctx.expect(!missing_ok, "parse_create_options requires id");
}

void test_parse_exec_options(TestContext& ctx) {
    ExecOptions options;
    std::vector<std::string> args = {
            "runtime", "--detach", "--pid-file", "/tmp/exec.pid", "demo", "/bin/echo", "hello"
    };
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    bool ok = parse_exec_options(static_cast<int>(args.size()), argv.data(), options);
    ctx.expect(ok, "parse_exec_options success");
    if (!ok) {
        return;
    }
    ctx.expect(options.detach, "parse_exec_options detach");
    ctx.expect(options.pid_file == "/tmp/exec.pid", "parse_exec_options pid file", options.pid_file);
    ctx.expect(options.id == "demo", "parse_exec_options id", options.id);
    ctx.expect(options.args.size() == 2, "parse_exec_options args size");
    ctx.expect(options.args.front() == "/bin/echo", "parse_exec_options arg0", options.args.empty() ? "" : options.args.front());

    ExecOptions invalid_opts;
    std::vector<std::string> invalid = {"runtime", "--detach"};
    std::vector<char*> invalid_argv;
    invalid_argv.reserve(invalid.size());
    for (auto& arg : invalid) {
        invalid_argv.push_back(const_cast<char*>(arg.c_str()));
    }
    int stderr_copy = dup(fileno(stderr));
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, fileno(stderr));
    close(devnull);
    bool invalid_ok = parse_exec_options(static_cast<int>(invalid.size()), invalid_argv.data(), invalid_opts);
    fflush(stderr);
    dup2(stderr_copy, fileno(stderr));
    close(stderr_copy);
    ctx.expect(!invalid_ok, "parse_exec_options requires id");
}

void test_parse_events_options(TestContext& ctx) {
    EventsOptions options;
    std::vector<std::string> args = {"runtime", "--stats", "--follow", "--interval", "250", "demo"};
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    bool ok = parse_events_options(static_cast<int>(args.size()), argv.data(), options);
    ctx.expect(ok, "parse_events_options success");
    if (!ok) {
        return;
    }
    ctx.expect(options.stats, "parse_events_options stats");
    ctx.expect(options.follow, "parse_events_options follow");
    ctx.expect(options.interval_ms == 250, "parse_events_options interval");
    ctx.expect(options.id == "demo", "parse_events_options id", options.id);
}

void test_load_config(TestContext& ctx) {
    std::string bundle = make_temp_dir("bundle-");
    std::string config_json = R"JSON(
{
  "ociVersion": "1.1.0",
  "root": {"path": "rootfs", "readonly": true},
  "process": {
    "terminal": true,
    "args": ["/bin/sh", "-c", "echo"],
    "env": ["FOO=bar", "PATH=/bin"],
    "cwd": "/work"
  },
  "hostname": "demo",
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "ipc", "path": "/proc/1/ns/ipc"}],
    "resources": {"memory": {"limit": 1048576}, "cpu": {"shares": 2048}},
    "uidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
    "gidMappings": [{"containerID": 0, "hostID": 1000, "size": 1}],
    "maskedPaths": ["/proc/kcore"],
    "readonlyPaths": ["/sys"],
    "rootfsPropagation": "rprivate",
    "cgroupsPath": "/user.slice/demo"
  },
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid"]}
  ],
  "annotations": {"example": "yes"},
  "hooks": {
    "createRuntime": [{"path": "/bin/true"}],
    "poststop": [{"path": "/bin/true"}]
  }
}
)JSON";
    const std::string config_path = path_join(bundle, "config.json");
    write_file(config_path, config_json);
    try {
        OCIConfig config = load_config(bundle);
        ctx.expect(config.ociVersion == "1.1.0", "load_config oci version", config.ociVersion);
        ctx.expect(config.root.readonly, "load_config root readonly");
        ctx.expect(config.process.terminal, "load_config process terminal");
        ctx.expect(config.process.args.size() == 3, "load_config args size");
        ctx.expect(config.process.env.front() == "FOO=bar", "load_config env value");
        ctx.expect(config.hostname == "demo", "load_config hostname", config.hostname);
        ctx.expect(!config.linux.namespaces.empty(), "load_config namespaces parsed");
        ctx.expect(config.linux.resources.cpu_shares == 2048, "load_config cpu shares");
        ctx.expect(config.mounts.size() == 1, "load_config mounts size");
        ctx.expect(config.annotations.at("example") == "yes", "load_config annotations");
        ctx.expect(!config.hooks.create_runtime.empty(), "load_config hooks createRuntime");
    } catch (const std::exception& e) {
        ctx.expect(false, "load_config threw", e.what());
    }
    remove_tree(bundle);
}

void test_filesystem_helpers(TestContext& ctx) {
    std::string base = make_temp_dir("fs-");
    std::string nested = path_join(base, "nested");
    ctx.expect(ensure_directory(nested, 0700), "ensure_directory creates nested");
    std::string file_path = path_join(nested, "child/file.txt");
    ctx.expect(ensure_file(file_path, 0600), "ensure_file creates file");
    ctx.expect(access(file_path.c_str(), F_OK) == 0, "ensure_file file exists", file_path);

    ctx.expect(container_absolute_path("/rootfs", "etc/passwd") == "/rootfs/etc/passwd",
               "container_absolute_path relative");
    ctx.expect(container_absolute_path("/rootfs", "/dev/null") == "/rootfs/dev/null",
               "container_absolute_path absolute");

    ctx.expect(propagation_flag_from_string("rshared") == (MS_SHARED | MS_REC),
               "propagation_flag_from_string rshared");

    ParsedMountOptions parsed = parse_mount_options({"bind", "ro", "nosuid", "size=64k", "shared"});
    ctx.expect((parsed.flags & MS_BIND) != 0, "parse_mount_options bind flag");
    ctx.expect(parsed.bind_readonly, "parse_mount_options bind readonly");
    ctx.expect(parsed.has_propagation, "parse_mount_options propagation flag");
    ctx.expect(parsed.data == "size=64k", "parse_mount_options data", parsed.data);

    ctx.expect(join_strings({"a", "b", "c"}, ":") == "a:b:c", "join_strings colon");

    std::string runtime_root = path_join(base, "state");
    g_global_options.root_path = runtime_root;
    ctx.expect(ensure_runtime_root_directory(), "ensure_runtime_root_directory success");
    ctx.expect(access(runtime_root.c_str(), F_OK) == 0, "ensure_runtime_root_directory exists", runtime_root);

    std::string fallback = fallback_state_root();
    ctx.expect(fallback.find(std::to_string(geteuid())) != std::string::npos,
               "fallback_state_root includes uid", fallback);

    std::string xdg_dir = make_temp_dir("xdg-");
    setenv("XDG_RUNTIME_DIR", xdg_dir.c_str(), 1);
    std::string default_root = default_state_root();
    ctx.expect(default_root == path_join(xdg_dir, "mruntime"), "default_state_root uses XDG", default_root);
    unsetenv("XDG_RUNTIME_DIR");
    remove_tree(xdg_dir);

    remove_tree(base);
}

void test_state_serialization(TestContext& ctx) {
    ContainerState state;
    state.version = "1.0";
    state.oci_version = "1.0";
    state.id = "demo";
    state.pid = 1234;
    state.status = "running";
    state.bundle_path = "/tmp/bundle";
    state.annotations["key"] = "value";

    std::string json_text = state.to_json();
    ContainerState parsed = ContainerState::from_json(json_text);
    ctx.expect(parsed.id == state.id, "ContainerState from_json id", parsed.id);
    ctx.expect(parsed.annotations.at("key") == "value", "ContainerState from_json annotation", parsed.annotations["key"]);

    const std::string root = test_state_root();
    ctx.expect(save_state(state), "save_state success");
    ContainerState loaded = load_state(state.id);
    ctx.expect(loaded.status == state.status, "load_state status", loaded.status);
    ctx.expect(get_fifo_path(state.id).find(state.id) != std::string::npos, "get_fifo_path contains id");
    ctx.expect(events_file_path(state.id).find("events.log") != std::string::npos, "events_file_path suffix");
    cleanup_state_root(root);
}

void test_record_event(TestContext& ctx) {
    const std::string root = test_state_root();
    const std::string container_id = "event-test";
    ContainerState state;
    state.version = RUNTIME_VERSION;
    state.oci_version = RUNTIME_VERSION;
    state.id = container_id;
    state.status = "created";
    state.pid = 42;
    state.bundle_path = "/tmp";
    record_state_event(state);
    std::string events_path = events_file_path(container_id);
    std::ifstream ifs(events_path);
    ctx.expect(static_cast<bool>(ifs), "record_event file exists", events_path);
    if (ifs) {
        std::string line;
        std::getline(ifs, line);
        ctx.expect(!line.empty(), "record_event line non-empty");
        if (!line.empty()) {
            json entry = json::parse(line, nullptr, false);
            ctx.expect(!entry.is_discarded(), "record_event parses as json");
            ctx.expect(entry["type"] == "state", "record_event type field");
            ctx.expect(entry["id"] == container_id, "record_event id field");
            ctx.expect(entry["data"]["status"] == "created", "record_event status field");
            ctx.expect(entry["data"]["pid"] == 42, "record_event pid field");
        }
    }
    cleanup_state_root(root);
}

void test_console_helpers(TestContext& ctx) {
    ConsolePair pair;
    std::string error;
    bool ok = allocate_console_pair(pair, error);
    if (!ok) {
        bool permission_issue = error.find("Permission denied") != std::string::npos;
        if (permission_issue) {
            ctx.expect(true, "allocate_console_pair skipped (insufficient permissions)");
        } else {
            ctx.expect(false, "allocate_console_pair success", error);
        }
        return;
    }
    ctx.expect(true, "allocate_console_pair success");
    ctx.expect(pair.master_fd >= 0 && pair.slave_fd >= 0, "allocate_console_pair fds valid");

    std::string sock_dir = make_temp_dir("console-");
    std::string sock_path = path_join(sock_dir, "pty.sock");
    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ctx.expect(server >= 0, "console server socket");
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
    int bind_rc = bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ctx.expect(bind_rc == 0, "console server bind", std::strerror(errno));
    ctx.expect(listen(server, 1) == 0, "console server listen", std::strerror(errno));

    std::promise<void> accepted_promise;
    auto accepted_future = accepted_promise.get_future();
    std::atomic<bool> payload_received{false};
    std::atomic<bool> fd_received{false};

    std::thread accept_thread([&] {
        int client = accept(server, nullptr, nullptr);
        if (client >= 0) {
            char buffer[128] = {0};
            char control[CMSG_SPACE(sizeof(int))];
            std::memset(control, 0, sizeof(control));
            struct iovec iov {};
            iov.iov_base = buffer;
            iov.iov_len = sizeof(buffer);
            struct msghdr msg {};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control;
            msg.msg_controllen = sizeof(control);
            ssize_t n = recvmsg(client, &msg, 0);
            if (n > 0) {
                payload_received = true;
                for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                        int received_fd = -1;
                        std::memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
                        if (received_fd >= 0) {
                            fd_received = true;
                            close(received_fd);
                        }
                    }
                }
            }
            close(client);
        }
        accepted_promise.set_value();
    });

    bool sent = send_console_fd(pair, sock_path, error);
    ctx.expect(sent, "send_console_fd success", error);
    accepted_future.wait_for(std::chrono::seconds(2));
    accept_thread.join();
    ctx.expect(payload_received.load(), "console payload received");
    ctx.expect(fd_received.load(), "console fd received");

    close(server);
    unlink(sock_path.c_str());
    remove_tree(sock_dir);
    close_console_pair(pair);
}

void test_cpu_shares_to_weight(TestContext& ctx) {
    ctx.expect(cpu_shares_to_weight(0) == 100, "cpu_shares_to_weight default");
    ctx.expect(cpu_shares_to_weight(1) == 1, "cpu_shares_to_weight min");
    ctx.expect(cpu_shares_to_weight(1024) > cpu_shares_to_weight(10), "cpu_shares_to_weight ordering");
}

void test_run_hook_sequence(TestContext& ctx) {
    std::string dir = make_temp_dir("hooks-");
    std::string hook_script = path_join(dir, "hook.sh");
    std::string output_path = path_join(dir, "hook-output.json");
    write_file(hook_script, "#!/bin/sh\ncat > \"$HOOK_OUT\"\n");
    chmod(hook_script.c_str(), 0755);

    HookConfig hook;
    hook.path = hook_script;
    hook.env.push_back("HOOK_OUT=" + output_path);

    ContainerState state;
    state.id = "hook-demo";
    state.status = "created";
    state.pid = 99;
    state.bundle_path = dir;

    std::vector<HookConfig> hooks = {hook};
    bool ok = run_hook_sequence(hooks, state, "createRuntime");
    ctx.expect(ok, "run_hook_sequence success");
    ctx.expect(access(output_path.c_str(), F_OK) == 0, "run_hook_sequence output created");
    std::string payload = read_file(output_path);
    ctx.expect(payload.find("hook-demo") != std::string::npos, "run_hook_sequence payload contains id");

    unlink(output_path.c_str());
    bool skipped = run_hook_sequence(hooks, state, "createRuntime");
    ctx.expect(skipped, "run_hook_sequence enforce once");
    ctx.expect(access(output_path.c_str(), F_OK) != 0, "run_hook_sequence second call skipped");

    std::string failing_script = path_join(dir, "fail.sh");
    write_file(failing_script, "#!/bin/sh\nexit 1\n");
    chmod(failing_script.c_str(), 0755);
    HookConfig failing;
    failing.path = failing_script;
    ContainerState failure_state;
    failure_state.id = "hook-demo";
    failure_state.status = "created";
    failure_state.pid = 100;
    failure_state.bundle_path = dir;
    bool fail = run_hook_sequence({failing}, failure_state, "poststop");
    ctx.expect(!fail, "run_hook_sequence failure propagates");

    remove_tree(dir);
}

void test_configure_log_destination(TestContext& ctx) {
    std::string dir = make_temp_dir("logs-");
    std::string log_path = path_join(dir, "runtime.log");
    g_global_options.debug = true;
    std::streambuf* original_cerr = std::cerr.rdbuf();
    bool ok = configure_log_destination(log_path);
    ctx.expect(ok, "configure_log_destination success");
    log_debug("debug message for log file");
    std::cerr << std::flush;
    std::string contents = read_file(log_path);
    ctx.expect(contents.find("debug message") != std::string::npos, "log_debug writes to log", contents);
    std::cerr.rdbuf(original_cerr);
    remove_tree(dir);
}

int main() {
    TestContext ctx;

    test_iso8601_format(ctx);
    test_collect_process_tree(ctx);
    test_wait_for_process(ctx);
    test_parse_create_options(ctx);
    test_parse_exec_options(ctx);
    test_parse_events_options(ctx);
    test_load_config(ctx);
    test_filesystem_helpers(ctx);
    test_state_serialization(ctx);
    test_record_event(ctx);
    test_console_helpers(ctx);
    test_cpu_shares_to_weight(ctx);
    test_run_hook_sequence(ctx);
    test_configure_log_destination(ctx);

    std::cout << "[TEST SUMMARY] Passed: " << ctx.passed << ", Failed: " << ctx.failed << std::endl;
    return ctx.failed == 0 ? 0 : 1;
}
