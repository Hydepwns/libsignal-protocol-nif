cmake_minimum_required(VERSION 3.10)
project(signal_nif C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find libsodium with better error handling
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

if(NOT SODIUM_FOUND)
    message(FATAL_ERROR "libsodium not found. Please install libsodium-dev (Ubuntu/Debian) or libsodium (macOS)")
endif()

# Use pkg-config results
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})
set(SODIUM_LIBRARIES ${SODIUM_LIBRARIES})

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

# Add include directories
include_directories(${ERLANG_INCLUDE_DIR})

# Add source files - use the fixed version
add_library(signal_nif SHARED
    signal_nif.c
)

# Add the libsignal_protocol_nif library
add_library(libsignal_protocol_nif SHARED
    libsignal_protocol_nif.c
)

# Add the new v2 libsignal_protocol_nif_v2 library with clean function table
add_library(libsignal_protocol_nif_v2 SHARED
    libsignal_protocol_nif_v2.c
)

# Link libsodium to all libraries
target_link_libraries(signal_nif ${SODIUM_LIBRARIES})
target_link_libraries(libsignal_protocol_nif ${SODIUM_LIBRARIES})
target_link_libraries(libsignal_protocol_nif_v2 ${SODIUM_LIBRARIES})

# Remove explicit erl_nif linking; use dynamic lookup on macOS
if(APPLE)
    foreach(target signal_nif libsignal_protocol_nif libsignal_protocol_nif_v2)
        target_link_libraries(${target} ${SODIUM_LIBRARIES})
        target_link_options(${target} PRIVATE "-undefined" "dynamic_lookup")
    endforeach()
else()
    foreach(target signal_nif libsignal_protocol_nif libsignal_protocol_nif_v2)
        target_link_libraries(${target} ${SODIUM_LIBRARIES})
    endforeach()
endif()

# Set output directory and name for signal_nif
set_target_properties(signal_nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "signal_nif"
    PREFIX ""  # Remove the "lib" prefix
)

# Set output directory and name for libsignal_protocol_nif
set_target_properties(libsignal_protocol_nif PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "libsignal_protocol_nif"
    PREFIX ""  # Remove the "lib" prefix
)

# Set output directory and name for libsignal_protocol_nif_v2
set_target_properties(libsignal_protocol_nif_v2 PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../priv"
    OUTPUT_NAME "libsignal_protocol_nif_v2"
    PREFIX ""  # Remove the "lib" prefix
)

# Set compile flags based on platform
if(APPLE)
    set_target_properties(signal_nif PROPERTIES
        SUFFIX ".dylib"
    )
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".dylib"
    )
    set_target_properties(libsignal_protocol_nif_v2 PROPERTIES
        SUFFIX ".dylib"
    )
elseif(UNIX)
    set_target_properties(signal_nif PROPERTIES
        SUFFIX ".so"
    )
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".so"
    )
    set_target_properties(libsignal_protocol_nif_v2 PROPERTIES
        SUFFIX ".so"
    )
elseif(WIN32)
    set_target_properties(signal_nif PROPERTIES
        SUFFIX ".dll"
    )
    set_target_properties(libsignal_protocol_nif PROPERTIES
        SUFFIX ".dll"
    )
    set_target_properties(libsignal_protocol_nif_v2 PROPERTIES
        SUFFIX ".dll"
    )
endif() 