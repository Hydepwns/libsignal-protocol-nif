cmake_minimum_required(VERSION 3.10)
project(signal_nif)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find Erlang
find_package(Erlang REQUIRED)

# Add signal_nif library
add_library(signal_nif SHARED
    signal_nif.c
)

# Include directories
target_include_directories(signal_nif PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../protocol
    ${CMAKE_CURRENT_SOURCE_DIR}/../crypto
    ${ERLANG_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(signal_nif
    signal_protocol
    crypto
    ${ERLANG_LIBRARIES}
)

# Set compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(signal_nif PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wno-unused-parameter
        -fPIC
    )
elseif(MSVC)
    target_compile_options(signal_nif PRIVATE
        /W4
        /WX
        /wd4100  # Unused parameter
    )
endif()

# Set output name to match Erlang's expectations
set_target_properties(signal_nif PROPERTIES
    PREFIX ""
    OUTPUT_NAME "signal_nif"
)

# Install rules
install(TARGETS signal_nif
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
) 