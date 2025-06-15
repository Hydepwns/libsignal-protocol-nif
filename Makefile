# Variables
ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
ERL_INTERFACE_PATH = $(shell erl -eval 'io:format("~s", [code:lib_dir(erl_interface, include)])' -s init stop -noshell)
CFLAGS = -I$(ERLANG_PATH) -I$(ERL_INTERFACE_PATH) -Iinclude -fPIC -O3 -Wall -Wextra
LDFLAGS = -L$(shell erl -eval 'io:format("~s", [code:lib_dir(erl_interface, lib)])' -s init stop -noshell)

# Platform-specific settings
ifeq ($(shell uname),Darwin)
    # macOS - handle both Intel and Apple Silicon
    ifeq ($(shell uname -m),arm64)
        CFLAGS += -I/opt/homebrew/opt/openssl/include
        LDFLAGS += -L/opt/homebrew/opt/openssl/lib
    else
        CFLAGS += -I/usr/local/opt/openssl/include
        LDFLAGS += -L/usr/local/opt/openssl/lib twice
    endif
    SHARED_EXT = dylib
else ifeq ($(OS),Windows_NT)
    # Windows
    SHARED_EXT = dll
else
    # Linux
    CFLAGS += -I/usr/include/openssl
    LDFLAGS += -L/usr/lib
    SHARED_EXT = so
endif

# Build targets
.PHONY: all clean test deps install

# Default target
all: build

BUILD_DIR = c_src/build

# Build the NIF
build: $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. && make
	mkdir -p ../../priv
	cp priv/libsignal_protocol_nif.* ../../priv/

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf priv/*.so priv/*.dylib priv/*.dll

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Run tests
test:
	rebar3 ct

# Install dependencies
deps:
	rebar3 get-deps
	rebar3 compile

# Build and install
install: build
	rebar3 compile
	rebar3 install

# Help target
help:
	@echo "Available targets:"
	@echo "  build        - Build all components"
	@echo "  clean        - Clean all build artifacts"
	@echo "  test         - Run all tests"
	@echo "  deps         - Install dependencies"
	@echo "  install      - Build and install"
	@echo "  help         - Show this help message" 