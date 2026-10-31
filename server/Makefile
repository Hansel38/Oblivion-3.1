# Makefile for Oblivion Server (Linux/Debian)
# Usage: make | make clean | make install

CXX ?= g++
CXXFLAGS += -std=c++17 -Wall -Wextra -O2 -pthread
CPPFLAGS ?=
LDLIBS += -lssl -lcrypto -pthread

INCLUDE_DIR := include
SRC_DIR := src
BUILD_DIR := build
TARGET := oblivion-server
OBJECTS := $(BUILD_DIR)/server_linux.o $(BUILD_DIR)/secret_obf.o
DEPS := $(OBJECTS:.o=.d)

.PHONY: all test integration-test clean install uninstall

all: $(TARGET)

TEST_TARGET := $(BUILD_DIR)/heartbeat_auth_test

test: $(TEST_TARGET)
	./$(TEST_TARGET)

integration-test: $(TARGET)
	python3 ../tests/heartbeat_integration.py ./$(TARGET)

$(TEST_TARGET): ../tests/heartbeat_auth_test.cpp ../common/heartbeat_auth.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I../common -o $@ $< $(LDLIBS)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/server_linux.o: server_linux.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(INCLUDE_DIR) -MMD -MP -c $< -o $@

$(BUILD_DIR)/secret_obf.o: $(SRC_DIR)/secret_obf.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I$(INCLUDE_DIR) -MMD -MP -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "Build complete: $(TARGET)"

clean:
	rm -rf $(BUILD_DIR)
	rm -f server_linux.o $(SRC_DIR)/secret_obf.o $(TARGET)
	@echo "Clean complete"

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/$(TARGET)
	@if [ ! -e /usr/local/bin/bans.txt ]; then \
		install -m 0644 bans.txt /usr/local/bin/bans.txt; \
		echo "Installed initial ban list to /usr/local/bin/bans.txt"; \
	else \
		echo "Preserving existing /usr/local/bin/bans.txt"; \
	fi
	@echo "Installed to /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled from /usr/local/bin/$(TARGET)"

-include $(DEPS)
