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
        LDFLAGS += -L/usr/local/opt/openssl/lib
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
.PHONY: all clean test test-clean deps install perf-test perf-monitor docker-build docker-test release dev-setup dev-test monitor-memory monitor-cache help

# Default target
all: build

PRIV_DIR = priv
BUILD_DIR = c_src/build

build: $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. && make
	mkdir -p $(PRIV_DIR)
	# Copy NIF to both default and test profile priv directories
	mkdir -p _build/default/lib/libsignal_protocol_nif/priv
	mkdir -p _build/test/lib/libsignal_protocol_nif/priv
	cp priv/libsignal_protocol_nif.dylib _build/default/lib/libsignal_protocol_nif/priv/ || true
	cp priv/libsignal_protocol_nif.dylib _build/test/lib/libsignal_protocol_nif/priv/ || true

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf priv/*.so priv/*.dylib priv/*.dll

# Clean test artifacts
test-clean:
	rm -rf tmp/
	rm -f *.log *.html *.xml *.cover

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Create test directories
test-dirs:
	mkdir -p tmp/ct_logs
	mkdir -p tmp/cover
	mkdir -p tmp/doc
	mkdir -p tmp/perf

# Run tests
test: test-dirs
	DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib rebar3 ct

# Run tests with coverage
test-cover: test-dirs
	DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib rebar3 ct --cover

# Run performance tests
perf-test: test-dirs build
	@echo "Running performance benchmarks..."
	DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib erl -noshell -pa ebin -pa test -eval "performance_test:run_benchmarks(), halt()."

# Run performance monitoring
perf-monitor: test-dirs build
	@echo "Starting performance monitoring..."
	DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib erl -noshell -pa ebin -pa test -eval "performance_test:run_benchmarks(), timer:sleep(5000), performance_test:run_benchmarks(), halt()."

# Generate documentation
docs: test-dirs
	rebar3 edoc

# Install dependencies
deps:
	rebar3 get-deps
	rebar3 compile

# Build and install
install: build
	rebar3 compile
	rebar3 install

# Docker targets
docker-build:
	@echo "Building Docker images..."
	docker build --target erlang-build -t libsignal-protocol-nif:erlang .
	docker build --target elixir-build -t libsignal-protocol-nif:elixir .
	docker build --target gleam-build -t libsignal-protocol-nif:gleam .
	docker build --target production -t libsignal-protocol-nif:latest .

docker-test:
	@echo "Running tests in Docker..."
	docker-compose up --abort-on-container-exit erlang-test
	docker-compose up --abort-on-container-exit elixir-test
	docker-compose up --abort-on-container-exit gleam-test

docker-perf:
	@echo "Running performance tests in Docker..."
	docker-compose up --abort-on-container-exit perf-test

# Release automation
release:
	@echo "Creating release..."
	./scripts/release.sh

release-patch:
	@echo "Creating patch release..."
	./scripts/release.sh patch

release-minor:
	@echo "Creating minor release..."
	./scripts/release.sh minor

release-major:
	@echo "Creating major release..."
	./scripts/release.sh major

# Development targets
dev-setup: deps build test-dirs
	@echo "Development environment setup complete"

dev-test: test perf-test
	@echo "All tests completed"

# Monitoring targets
monitor-memory:
	@echo "Monitoring memory usage..."
	erl -noshell -pa ebin -eval "performance_test:benchmark_memory_usage(1000), halt()."

monitor-cache:
	@echo "Monitoring cache performance..."
	erl -noshell -pa ebin -eval "performance_test:benchmark_cache_performance(1000), halt()."

# Help target
help:
	@echo "Available targets:"
	@echo "  build          - Build all components"
	@echo "  clean          - Clean all build artifacts"
	@echo "  test-clean     - Clean all test artifacts"
	@echo "  test           - Run all tests"
	@echo "  test-cover     - Run tests with coverage"
	@echo "  perf-test      - Run performance benchmarks"
	@echo "  perf-monitor   - Run performance monitoring"
	@echo "  docs           - Generate documentation"
	@echo "  deps           - Install dependencies"
	@echo "  install        - Build and install"
	@echo "  docker-build   - Build Docker images"
	@echo "  docker-test    - Run tests in Docker"
	@echo "  docker-perf    - Run performance tests in Docker"
	@echo "  release        - Create a new release"
	@echo "  release-patch  - Create a patch release"
	@echo "  release-minor  - Create a minor release"
	@echo "  release-major  - Create a major release"
	@echo "  dev-setup      - Setup development environment"
	@echo "  dev-test       - Run all development tests"
	@echo "  monitor-memory - Monitor memory usage"
	@echo "  monitor-cache  - Monitor cache performance"
	@echo "  help           - Show this help message" 