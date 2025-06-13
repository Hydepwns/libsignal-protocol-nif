# FindOpenSSL.cmake
# Finds the OpenSSL library
#
# This will define the following variables:
#
#   OPENSSL_FOUND        - True if the system has OpenSSL
#   OPENSSL_INCLUDE_DIR  - OpenSSL include directory
#   OPENSSL_LIBRARIES    - OpenSSL libraries
#   OPENSSL_VERSION      - OpenSSL version

include(FindPackageHandleStandardArgs)

# Check for macOS-specific paths
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        set(OPENSSL_POSSIBLE_INCLUDE_DIRS
            /opt/homebrew/opt/openssl/include
            /opt/homebrew/include
        )
        set(OPENSSL_POSSIBLE_LIB_DIRS
            /opt/homebrew/opt/openssl/lib
            /opt/homebrew/lib
        )
    else()
        set(OPENSSL_POSSIBLE_INCLUDE_DIRS
            /usr/local/opt/openssl/include
            /usr/local/include
        )
        set(OPENSSL_POSSIBLE_LIB_DIRS
            /usr/local/opt/openssl/lib
            /usr/local/lib
        )
    endif()
endif()

# Find include directory
find_path(OPENSSL_INCLUDE_DIR
    NAMES openssl/ssl.h
    PATHS ${OPENSSL_POSSIBLE_INCLUDE_DIRS}
    DOC "OpenSSL include directory"
)

# Find libraries
find_library(OPENSSL_SSL_LIBRARY
    NAMES ssl
    PATHS ${OPENSSL_POSSIBLE_LIB_DIRS}
    DOC "OpenSSL SSL library"
)

find_library(OPENSSL_CRYPTO_LIBRARY
    NAMES crypto
    PATHS ${OPENSSL_POSSIBLE_LIB_DIRS}
    DOC "OpenSSL Crypto library"
)

# Set OpenSSL libraries
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

# Try to get version
if(OPENSSL_INCLUDE_DIR)
    file(STRINGS "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h" OPENSSL_VERSION_LINE
        REGEX "^#define OPENSSL_VERSION_NUMBER[ \t]+0x[0-9a-fA-F]+.*$")
    string(REGEX REPLACE "^#define OPENSSL_VERSION_NUMBER[ \t]+0x([0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F]).*$"
        "\\1.\\2.\\3" OPENSSL_VERSION "${OPENSSL_VERSION_LINE}")
endif()

# Handle the QUIETLY and REQUIRED arguments and set OPENSSL_FOUND
find_package_handle_standard_args(OpenSSL
    REQUIRED_VARS OPENSSL_LIBRARIES OPENSSL_INCLUDE_DIR
    VERSION_VAR OPENSSL_VERSION
)

mark_as_advanced(OPENSSL_INCLUDE_DIR OPENSSL_LIBRARIES) 