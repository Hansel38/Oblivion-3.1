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
INSTALL_DIR ?= /usr/local/bin
TLS_CERT_FILE ?= server-cert.pem
TLS_KEY_FILE ?= server-key.pem
OBJECTS := $(BUILD_DIR)/server_linux.o $(BUILD_DIR)/secret_obf.o
DEPS := $(OBJECTS:.o=.d)

.PHONY: all test integration-test production-check clean install uninstall

all: $(TARGET)

TEST_TARGET := $(BUILD_DIR)/heartbeat_auth_test
HWID_TEST_TARGET := $(BUILD_DIR)/hwid_identifier_validation_test
TLS_PROBE_TARGET := $(BUILD_DIR)/tls_client_probe

PATH_POLICY_TEST_TARGET := $(BUILD_DIR)/windows_path_policy_test
AUTHENTICODE_POLICY_TEST_TARGET := $(BUILD_DIR)/authenticode_verdict_policy_test

test: $(TEST_TARGET) $(HWID_TEST_TARGET) $(PATH_POLICY_TEST_TARGET) $(AUTHENTICODE_POLICY_TEST_TARGET)
	./$(TEST_TARGET)
	./$(HWID_TEST_TARGET)
	./$(PATH_POLICY_TEST_TARGET)
	./$(AUTHENTICODE_POLICY_TEST_TARGET)
	python3 ../tests/test_integrity_manifest_generator.py
	python3 ../tests/test_production_network_config.py
	python3 ../tests/test_production_readiness.py

production-check:
	@test -n "$(OBLIVION_PRODUCTION_GAME_DIR)" || (echo "[ERROR] Set OBLIVION_PRODUCTION_GAME_DIR to the exact package distributed to players." >&2; exit 2)
	@test -n "$(OBLIVION_SERVER_HOST)" || (echo "[ERROR] Set OBLIVION_SERVER_HOST to the configured DNS name or IP address." >&2; exit 2)
	@test -n "$(OBLIVION_TLS_PIN_SHA256)" || (echo "[ERROR] Set OBLIVION_TLS_PIN_SHA256 to the deployed leaf-certificate pin list." >&2; exit 2)
	python3 ../tools/check_production_readiness.py --game-dir "$(OBLIVION_PRODUCTION_GAME_DIR)" --network-config "../client/include/production_network_config.generated.h" --tls-cert "$(TLS_CERT_FILE)" --tls-key "$(TLS_KEY_FILE)" --server-host "$(OBLIVION_SERVER_HOST)" --tls-pin-sha256 "$(OBLIVION_TLS_PIN_SHA256)"

integration-test: $(TARGET) $(TLS_PROBE_TARGET)
	python3 ../tests/heartbeat_integration.py ./$(TARGET) ./$(TLS_PROBE_TARGET)

$(TEST_TARGET): ../tests/heartbeat_auth_test.cpp ../common/heartbeat_auth.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I../common -o $@ $< $(LDLIBS)

$(HWID_TEST_TARGET): ../tests/hwid_identifier_validation_test.cpp ../client/include/hwid_identifier_validation.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I../client/include -o $@ $<

$(PATH_POLICY_TEST_TARGET): ../tests/windows_path_policy_test.cpp ../common/windows_path_policy.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I../common -o $@ $<

$(AUTHENTICODE_POLICY_TEST_TARGET): ../tests/authenticode_verdict_policy_test.cpp ../common/authenticode_verdict_policy.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I../common -o $@ $<

$(TLS_PROBE_TARGET): ../tests/tls_client_probe.cpp ../common/tls_transport.h | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -I../common -o $@ $< -lssl -lcrypto

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
	@set -eu; \
	if [ -f "$(TLS_CERT_FILE)" ] && [ -f "$(TLS_KEY_FILE)" ]; then \
		echo "TLS certificate/key source pair found: $(TLS_CERT_FILE), $(TLS_KEY_FILE)"; \
	elif [ -f "$(INSTALL_DIR)/server-cert.pem" ] && [ -f "$(INSTALL_DIR)/server-key.pem" ]; then \
		echo "Preserving existing TLS certificate/key in $(INSTALL_DIR)"; \
	elif [ -n "$(OBLIVION_TLS_CERT_FILE)" ] && [ -n "$(OBLIVION_TLS_KEY_FILE)" ] && \
	     [ -f "$(OBLIVION_TLS_CERT_FILE)" ] && [ -f "$(OBLIVION_TLS_KEY_FILE)" ]; then \
		echo "Using externally configured TLS certificate/key paths"; \
	else \
		echo "[ERROR] TLS certificate/key missing. Create server-cert.pem/server-key.pem, preserve an installed pair, or configure OBLIVION_TLS_CERT_FILE and OBLIVION_TLS_KEY_FILE."; \
		exit 1; \
	fi
	install -d -m 0755 "$(INSTALL_DIR)"
	install -m 0755 $(TARGET) "$(INSTALL_DIR)/$(TARGET)"
	@if [ -f "$(TLS_CERT_FILE)" ] && [ -f "$(TLS_KEY_FILE)" ]; then \
		install -m 0644 "$(TLS_CERT_FILE)" "$(INSTALL_DIR)/server-cert.pem"; \
		install -m 0600 "$(TLS_KEY_FILE)" "$(INSTALL_DIR)/server-key.pem"; \
		echo "Installed TLS certificate and private key to $(INSTALL_DIR)"; \
	fi
	@if [ ! -e "$(INSTALL_DIR)/bans.txt" ]; then \
		install -m 0644 bans.txt "$(INSTALL_DIR)/bans.txt"; \
		echo "Installed initial ban list to $(INSTALL_DIR)/bans.txt"; \
	else \
		echo "Preserving existing $(INSTALL_DIR)/bans.txt"; \
	fi
	@echo "Installed to $(INSTALL_DIR)/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled from /usr/local/bin/$(TARGET)"

-include $(DEPS)
