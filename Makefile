CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS =
SRC = main.cpp
TARGET = runtime
PREFIX = /usr/local
BIN_DIR = $(PREFIX)/bin

.PHONY: all clean install uninstall help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "Executable '$(TARGET)' has made."

clean:
	@echo "Deleting built OBJ"
	rm -f $(TARGET)
	@echo "Completed"

install: $(TARGET)
	@echo "'$(TARGET)' is installing to '$(BIN_DIR)'"
	@mkdir -p $(BIN_DIR)
	@install -m 0755 $(TARGET) $(BIN_DIR)
	@echo "Install is completed 'sudo $(TARGET)' to execute"

uninstall:
	@echo "'$(TARGET)' is deleting from '$(BIN_DIR)'"
	@rm -f $(BIN_DIR)/$(TARGET)
	@echo "Deleted!"

help:
	@echo "How to use:"
	@echo "  make           - Same to make all "
	@echo "  make all       - Build whole"
	@echo "  make clean     - Delete built OBJ"
	@echo "  make install   - Install the program to /usr/local/bin, Run with root"
	@echo "  make uninstall - Delete the Programs, Run with root access."
	@echo "  make help      - Show this help"

