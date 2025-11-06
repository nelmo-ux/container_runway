#include <algorithm>
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

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

std::string test_state_root() {
    std::string root = "/tmp/runway-test-" + std::to_string(getpid());
    ensure_directory(root, 0755);
    g_global_options.root_path = root;
    return root;
}

void cleanup_state_root(const std::string& root, const std::string& id) {
    std::string base = root;
    if (!base.empty() && base.back() == '/') {
        base.pop_back();
    }
    std::string event_dir = state_base_path() + id;
    std::string event_file = event_dir + "/events.log";
    unlink(event_file.c_str());
    rmdir(event_dir.c_str());
    rmdir(base.c_str());
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
    cleanup_state_root(root, container_id);
}

int main() {
    TestContext ctx;

    test_iso8601_format(ctx);
    test_collect_process_tree(ctx);
    test_parse_exec_options(ctx);
    test_parse_events_options(ctx);
    test_record_event(ctx);

    std::cout << "[TEST SUMMARY] Passed: " << ctx.passed << ", Failed: " << ctx.failed << std::endl;
    return ctx.failed == 0 ? 0 : 1;
}
