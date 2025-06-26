cmake_minimum_required(VERSION 3.10)
project(nif C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform-specific OpenSSL configuration
if(APPLE)
    # macOS - handle both Intel and Apple Silicon
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib/libcrypto.a;${OPENSSL_ROOT_DIR}/lib/libssl.a")
    include_directories(/opt/homebrew/opt/openssl@3/include)
elseif(UNIX AND NOT APPLE)
    # Linux - use system OpenSSL
    set(OPENSSL_ROOT_DIR "/usr")
    set(OPENSSL_INCLUDE_DIR "/usr/include/openssl")
    set(OPENSSL_LIBRARIES "crypto;ssl")
    include_directories(/usr/include/openssl)
elseif(WIN32)
    # Windows - use system OpenSSL
    set(OPENSSL_ROOT_DIR "C:/OpenSSL-Win64")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib/libcrypto.lib;${OPENSSL_ROOT_DIR}/lib/libssl.lib")
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
include_directories(${OPENSSL_INCLUDE_DIRS} ${ERLANG_INCLUDE_DIR})

# Add source files - modular structure
add_library(nif SHARED
    nif.c
    constants.h
    types.h
    utils/utils.c
    utils/utils.h
    utils/error_handling.c
    utils/error_handling.h
    keys/keys.c
    keys/keys.h
    session/session.c
    session/session.h
    cache/cache.c
    cache/cache.h
    crypto/crypto.c
    crypto/crypto.h
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
        LINK_FLAGS "-undefined dynamic_lookup \
        -Wl,-exported_symbol,_nif_init \
        -Wl,-exported_symbol,_nif_funcs \
        -Wl,-exported_symbol,_on_load \
        -Wl,-exported_symbol,_on_unload \
        -Wl,-exported_symbol,_generate_identity_key_pair \
        -Wl,-exported_symbol,_generate_pre_key \
        -Wl,-exported_symbol,_generate_signed_pre_key \
        -Wl,-exported_symbol,_create_session \
        -Wl,-exported_symbol,_process_pre_key_bundle \
        -Wl,-exported_symbol,_encrypt_message \
        -Wl,-exported_symbol,_decrypt_message \
        -Wl,-exported_symbol,_get_cache_stats \
        -Wl,-exported_symbol,_reset_cache_stats \
        -Wl,-exported_symbol,_set_cache_size \
        -Wl,-exported_symbol,_verify_signature \
        -Wl,-exported_symbol,_compute_key \
        -Wl,-exported_symbol,_generate_key_pair \
        -Wl,-exported_symbol,_generate_curve25519_key_pair \
        -Wl,-exported_symbol,_generate_ed25519_key_pair \
        -Wl,-exported_symbol,_validate_key_pair \
        -Wl,-exported_symbol,_private_to_public_key \
        -Wl,-rpath,@loader_path"
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

# Post-build step: copy and symlink for rebar3 test and default priv dirs (macOS)
if(APPLE)
    add_custom_command(TARGET nif POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/../_build/test/lib/nif/priv"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:nif>" "${CMAKE_SOURCE_DIR}/../_build/test/lib/nif/priv/nif.dylib"
        COMMAND ${CMAKE_COMMAND} -E create_symlink "nif.dylib" "${CMAKE_SOURCE_DIR}/../_build/test/lib/nif/priv/nif.so"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/../_build/default/lib/nif/priv"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:nif>" "${CMAKE_SOURCE_DIR}/../_build/default/lib/nif/priv/nif.dylib"
        COMMAND ${CMAKE_COMMAND} -E create_symlink "nif.dylib" "${CMAKE_SOURCE_DIR}/../_build/default/lib/nif/priv/nif.so"
    )
endif()
