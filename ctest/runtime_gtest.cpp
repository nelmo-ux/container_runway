#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <unistd.h>
#include <vector>

#define main runtime_cli_main
#include "../main.cpp"
#undef main

namespace fs = std::filesystem;

class RuntimeFixture : public ::testing::Test {
protected:
    std::string root;

    void SetUp() override {
        const testing::TestInfo* info = testing::UnitTest::GetInstance()->current_test_info();
        std::string test_name = info ? info->name() : "default";
        std::string safe_name = test_name;
        std::transform(safe_name.begin(), safe_name.end(), safe_name.begin(), [](unsigned char c) {
            return (std::isalnum(c) || c == '-' || c == '_') ? static_cast<char>(c) : '_';
        });
        root = "/tmp/runway-gtest-" + std::to_string(getpid()) + "-" + safe_name;
        ensure_directory(root, 0755);
        g_global_options.root_path = root;
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
};

TEST_F(RuntimeFixture, Iso8601NowProducesZuluTimeStamp) {
    std::string ts = iso8601_now();
    EXPECT_FALSE(ts.empty());
    EXPECT_EQ('Z', ts.back());
    EXPECT_NE(std::string::npos, ts.find('T'));
    EXPECT_NE(std::string::npos, ts.find('.'));
}

TEST_F(RuntimeFixture, CollectProcessTreeIncludesSelf) {
    pid_t self = getpid();
    std::vector<pid_t> pids = collect_process_tree(self);
    EXPECT_NE(pids.end(), std::find(pids.begin(), pids.end(), self));
}

TEST_F(RuntimeFixture, ParseExecOptionsHandlesFlags) {
    ExecOptions opts;
    std::vector<std::string> args = {
            "runtime",
            "--detach",
            "--pid-file",
            "/tmp/exec.pid",
            "demo",
            "/bin/echo",
            "hello"
    };
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    EXPECT_TRUE(parse_exec_options(static_cast<int>(argv.size()), argv.data(), opts));
    EXPECT_TRUE(opts.detach);
    EXPECT_EQ("/tmp/exec.pid", opts.pid_file);
    ASSERT_EQ("demo", opts.id);
    ASSERT_EQ(2u, opts.args.size());
    EXPECT_EQ("/bin/echo", opts.args[0]);
    EXPECT_EQ("hello", opts.args[1]);

    ::testing::internal::CaptureStderr();
    ExecOptions invalid;
    std::vector<std::string> invalid_args = {"runtime"};
    std::vector<char*> invalid_argv;
    for (auto& arg : invalid_args) {
        invalid_argv.push_back(const_cast<char*>(arg.c_str()));
    }
    EXPECT_FALSE(parse_exec_options(static_cast<int>(invalid_argv.size()), invalid_argv.data(), invalid));
    ::testing::internal::GetCapturedStderr();
}

TEST_F(RuntimeFixture, ParseEventsOptionsParsesInterval) {
    EventsOptions opts;
    std::vector<std::string> args = {
            "runtime",
            "--stats",
            "--follow",
            "--interval",
            "1500",
            "demo"
    };
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    EXPECT_TRUE(parse_events_options(static_cast<int>(argv.size()), argv.data(), opts));
    EXPECT_TRUE(opts.stats);
    EXPECT_TRUE(opts.follow);
    EXPECT_EQ(1500, opts.interval_ms);
    EXPECT_EQ("demo", opts.id);
}

TEST_F(RuntimeFixture, RecordEventWritesJsonLine) {
    std::string id = "record-event";
    record_event(id, "lifecycle", json{{"status", "created"}});
    fs::path event_path = fs::path(state_base_path()) / id / "events.log";
    ASSERT_TRUE(fs::exists(event_path));
    std::ifstream ifs(event_path);
    ASSERT_TRUE(ifs.good());
    std::string line;
    std::getline(ifs, line);
    ASSERT_FALSE(line.empty());
    json entry = json::parse(line, nullptr, false);
    ASSERT_FALSE(entry.is_discarded());
    EXPECT_EQ("lifecycle", entry["type"]);
    EXPECT_EQ(id, entry["id"]);
    EXPECT_EQ("created", entry["data"]["status"]);
}
