cmake_minimum_required(VERSION 3.10)
project(libsignal_protocol_nif C)

# Add cmake modules path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Erlang REQUIRED)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Get Erlang include paths
execute_process(
    COMMAND erl -eval "io:format(\"~s\", [lists:concat([code:root_dir(), \"/erts-\", erlang:system_info(version), \"/include\"])])" -s init stop -noshell
    OUTPUT_VARIABLE ERLANG_ERTS_INCLUDE_DIR
)

execute_process(
    COMMAND erl -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)])" -s init stop -noshell
    OUTPUT_VARIABLE ERLANG_EI_INCLUDE_DIR
)

# Add include directories
include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${ERLANG_ERTS_INCLUDE_DIR}
    ${ERLANG_EI_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set compile definitions
add_definitions(-DOPENSSL_API_COMPAT=0x10100000L)

# Add source files
set(SOURCES
    libsignal_protocol_nif.c
)

# Create shared library
add_library(libsignal_protocol_nif SHARED ${SOURCES})

# Get Erlang library paths
execute_process(
    COMMAND erl -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)])" -s init stop -noshell
    OUTPUT_VARIABLE ERLANG_LIB_DIR
)

execute_process(
    COMMAND erl -eval "io:format(\"~s\", [lists:concat([code:root_dir(), \"/erts-\", erlang:system_info(version), \"/lib\"])])" -s init stop -noshell
    OUTPUT_VARIABLE ERLANG_ERTS_LIB_DIR
)

# Link libraries
target_link_libraries(libsignal_protocol_nif
    ${OPENSSL_LIBRARIES}
)

# Set output directory
set_target_properties(libsignal_protocol_nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../priv
    OUTPUT_NAME "signal_protocol_nif"
)

# On macOS, allow undefined symbols for dynamic lookup (for NIFs)
if(APPLE)
    set_target_properties(libsignal_protocol_nif PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
endif()

# Install rules
install(TARGETS libsignal_protocol_nif
    LIBRARY DESTINATION priv
) 