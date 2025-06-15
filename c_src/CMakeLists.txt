cmake_minimum_required(VERSION 3.10)
project(libsignal_protocol_nif C)

# Set OpenSSL paths explicitly for arm64
set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib/libssl.dylib" "${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib")

# Find required packages
find_package(OpenSSL REQUIRED)

# Detect Erlang include directory automatically
execute_process(
  COMMAND erl -noshell -eval "io:format(\"~s\", [code:root_dir()]), halt()."
  OUTPUT_VARIABLE ERLANG_ROOT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(ERLANG_INCLUDE_DIR "${ERLANG_ROOT}/usr/include")
if(NOT EXISTS "${ERLANG_INCLUDE_DIR}")
  set(ERLANG_INCLUDE_DIR "${ERLANG_ROOT}/include")
endif()

# Detect Erlang lib directory automatically
set(ERLANG_LIB_DIR "${ERLANG_ROOT}/usr/lib")
if(NOT EXISTS "${ERLANG_LIB_DIR}")
  set(ERLANG_LIB_DIR "${ERLANG_ROOT}/lib")
endif()

# Add include directories
include_directories(${OPENSSL_INCLUDE_DIR} ${ERLANG_INCLUDE_DIR})

# Add source files
add_library(libsignal_protocol_nif SHARED
    libsignal_protocol_nif.c
)

# Set output directory and name
set_target_properties(libsignal_protocol_nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "signal_protocol_nif"
)

# Link libraries
target_link_libraries(libsignal_protocol_nif
    ${OPENSSL_LIBRARIES}
    ${ERLANG_LIB_DIR}/liberts.dylib
    ${ERLANG_LIB_DIR}/libei.dylib
)

# Set compile flags based on platform
if(APPLE)
    target_compile_definitions(libsignal_protocol_nif PRIVATE
        __APPLE__=1
        __DARWIN__=1
    )
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".dylib"
        COMPILE_FLAGS "-arch arm64"
        LINK_FLAGS "-undefined dynamic_lookup"
    )
elseif(UNIX)
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".so"
    )
elseif(WIN32)
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".dll"
    )
endif()

# Install rules
install(TARGETS libsignal_protocol_nif
    LIBRARY DESTINATION priv
)
