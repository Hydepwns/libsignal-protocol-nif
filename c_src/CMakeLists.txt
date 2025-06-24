cmake_minimum_required(VERSION 3.10)
project(nif C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set OpenSSL paths explicitly for Homebrew on Apple Silicon
if(APPLE)
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib/libcrypto.a;${OPENSSL_ROOT_DIR}/lib/libssl.a")
endif()

# Find required packages
find_package(OpenSSL REQUIRED)

# Detect Erlang include directory automatically
execute_process(
  COMMAND erl -noshell -eval "io:format(\"~s\", [code:root_dir()]), halt()."
  OUTPUT_VARIABLE ERLANG_ROOT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Try different possible Erlang include paths
set(ERLANG_INCLUDE_DIR "${ERLANG_ROOT}/usr/include")
if(NOT EXISTS "${ERLANG_INCLUDE_DIR}")
  set(ERLANG_INCLUDE_DIR "${ERLANG_ROOT}/include")
endif()

# Also try system paths for Erlang
if(NOT EXISTS "${ERLANG_INCLUDE_DIR}")
  set(ERLANG_INCLUDE_DIR "/opt/homebrew/lib/erlang/usr/include")
endif()

if(NOT EXISTS "${ERLANG_INCLUDE_DIR}")
  set(ERLANG_INCLUDE_DIR "/usr/local/lib/erlang/usr/include")
endif()

if(NOT EXISTS "${ERLANG_INCLUDE_DIR}")
  set(ERLANG_INCLUDE_DIR "/usr/lib/erlang/usr/include")
endif()

# Detect Erlang lib directory automatically
set(ERLANG_LIB_DIR "${ERLANG_ROOT}/usr/lib")
if(NOT EXISTS "${ERLANG_LIB_DIR}")
  set(ERLANG_LIB_DIR "${ERLANG_ROOT}/lib")
endif()

# Add include directories
if(APPLE)
    include_directories(/opt/homebrew/opt/openssl@3/include)
endif()
include_directories(${OPENSSL_INCLUDE_DIRS} ${ERLANG_INCLUDE_DIR})

# Add source files - only build the main NIF implementation
add_library(nif SHARED
    nif.c
    crypto/crypto.c
    protocol/protocol.c
    protocol/protocol.h
)

# Set output directory and name for nif
set_target_properties(nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "nif"
    PREFIX ""  # Remove the "lib" prefix
)

# Link libraries for nif
target_link_libraries(nif
    ${OPENSSL_LIBRARIES}
)

# Set compile flags based on platform
if(APPLE)
    target_compile_definitions(nif PRIVATE
        __APPLE__=1
        __DARWIN__=1
    )
    set_target_properties(nif PROPERTIES
        SUFFIX ".dylib"
        LINK_FLAGS "-undefined dynamic_lookup -Wl,-exported_symbol,_nif_init -Wl,-exported_symbol,_nif_funcs -Wl,-rpath,@loader_path"
    )
elseif(UNIX)
    set_target_properties(nif PROPERTIES
        SUFFIX ".so"
        LINK_FLAGS "-Wl,--export-dynamic"
    )
elseif(WIN32)
    set_target_properties(nif PROPERTIES
        SUFFIX ".dll"
        LINK_FLAGS "/EXPORT:nif_funcs"
    )
endif()

# Install rules
install(TARGETS nif
    LIBRARY DESTINATION priv
)
