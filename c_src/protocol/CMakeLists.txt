cmake_minimum_required(VERSION 3.10)
project(signal_protocol)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add signal_protocol library
add_library(signal_protocol STATIC
    signal_protocol.c
)

# Include directories
target_include_directories(signal_protocol PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../crypto
    ${OPENSSL_INCLUDE_DIR}
    ${ERLANG_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(signal_protocol
    crypto
    ${OPENSSL_LIBRARIES}
    ${ERLANG_LIBRARIES}
)

# Set compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(signal_protocol PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wno-unused-parameter
        -fPIC
    )
elseif(MSVC)
    target_compile_options(signal_protocol PRIVATE
        /W4
        /WX
        /wd4100  # Unused parameter
    )
endif()

# Install rules
install(TARGETS signal_protocol
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES signal_protocol.h
    DESTINATION include/signal_protocol
) 