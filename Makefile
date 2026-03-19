CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2 -Iinclude -I.
LDFLAGS =
RUNTIME_SRC = \
      src/runtime/config.cpp \
      src/runtime/options.cpp \
      src/runtime/filesystem.cpp \
      src/runtime/state.cpp \
      src/runtime/process.cpp \
      src/runtime/isolation.cpp \
      src/runtime/console.cpp \
      src/runtime/hooks.cpp
SRC = main.cpp $(RUNTIME_SRC)
TARGET = runtime
PREFIX = /usr/local
BIN_DIR = $(PREFIX)/bin
TEST_DIR = test
TEST_TARGET = $(TEST_DIR)/runtime_tests
BPFMOD_DIR = bpfMod_src
SECCOMP_FILTER = $(BPFMOD_DIR)/target/x86_64-unknown-linux-gnu/release/seccomp-filter

.PHONY: all clean install uninstall help test seccomp-filter

all: $(TARGET) seccomp-filter

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "Executable '$(TARGET)' has made."

seccomp-filter:
	cd $(BPFMOD_DIR) && LIBSECCOMP_LINK_TYPE=static LIBSECCOMP_LIB_PATH=/usr/lib/x86_64-linux-gnu RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
	@echo "seccomp-filter has made."

$(TEST_TARGET): $(TEST_DIR)/runtime_tests.cpp $(RUNTIME_SRC)
	$(CXX) $(CXXFLAGS) -o $(TEST_TARGET) $(TEST_DIR)/runtime_tests.cpp $(RUNTIME_SRC) $(LDFLAGS)
	@echo "Test binary '$(TEST_TARGET)' has made."

test: $(TEST_TARGET)
	./$(TEST_TARGET)

test-seccomp:
	cd $(BPFMOD_DIR) && cargo test
	@echo "seccomp-filter tests passed."

clean:
	@echo "Deleting built OBJ"
	rm -f $(TARGET) $(TEST_TARGET)
	cd $(BPFMOD_DIR) && cargo clean
	@echo "Completed"

install: $(TARGET) seccomp-filter
	@echo "'$(TARGET)' is installing to '$(BIN_DIR)'"
	@mkdir -p $(BIN_DIR)
	@install -m 0755 $(TARGET) $(BIN_DIR)
	@install -m 0755 $(SECCOMP_FILTER) $(BIN_DIR)
	@echo "Install is completed 'sudo $(TARGET)' to execute"

uninstall:
	@echo "'$(TARGET)' is deleting from '$(BIN_DIR)'"
	@rm -f $(BIN_DIR)/$(TARGET)
	@rm -f $(BIN_DIR)/seccomp-filter
	@echo "Deleted!"

help:
	@echo "How to use:"
	@echo "  make              - Same to make all "
	@echo "  make all          - Build whole (runtime + seccomp-filter)"
	@echo "  make runtime      - Build runtime only"
	@echo "  make seccomp-filter - Build seccomp-filter only"
	@echo "  make clean        - Delete built OBJ"
	@echo "  make install      - Install the program to /usr/local/bin, Run with root"
	@echo "  make uninstall    - Delete the Programs, Run with root access."
	@echo "  make test         - Build and run runtime unit tests"
	@echo "  make test-seccomp - Run seccomp-filter unit tests"
	@echo "  make help         - Show this help"
