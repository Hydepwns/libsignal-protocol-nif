cmake_minimum_required(VERSION 3.10)
project(crypto)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add crypto library
add_library(crypto STATIC
    crypto.c
)

# Include directories
target_include_directories(crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(crypto
    ${OPENSSL_LIBRARIES}
)

# Set compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(crypto PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wno-unused-parameter
        -fPIC
    )
elseif(MSVC)
    target_compile_options(crypto PRIVATE
        /W4
        /WX
        /wd4100  # Unused parameter
    )
endif()

# Install rules
install(TARGETS crypto
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES crypto.h
    DESTINATION include/crypto
) 