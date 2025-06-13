# FindErlang.cmake
# Finds the Erlang installation
#
# This will define the following variables:
#
#   ERLANG_FOUND        - True if the system has Erlang
#   ERLANG_INCLUDE_DIRS - Erlang include directory
#   ERLANG_LIBRARIES    - Erlang libraries
#   ERLANG_VERSION      - Erlang version

# Find erl
find_program(ERL_EXECUTABLE erl)
if(NOT ERL_EXECUTABLE)
    message(FATAL_ERROR "Erlang not found. Please install Erlang.")
endif()

# Get Erlang version
execute_process(
    COMMAND ${ERL_EXECUTABLE} -noshell -eval "io:format(\"~s\", [erlang:system_info(version)]), halt()." -s init stop
    OUTPUT_VARIABLE ERLANG_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get Erlang root directory
execute_process(
    COMMAND ${ERL_EXECUTABLE} -noshell -eval "io:format(\"~s\", [code:root_dir()]), halt()." -s init stop
    OUTPUT_VARIABLE ERLANG_ROOT_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Set Erlang include directories
set(ERLANG_INCLUDE_DIRS
    ${ERLANG_ROOT_DIR}/usr/include
    ${ERLANG_ROOT_DIR}/erts-${ERLANG_VERSION}/include
)

# Set Erlang libraries
set(ERLANG_LIBRARIES
    ${ERLANG_ROOT_DIR}/usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Erlang
    REQUIRED_VARS ERL_EXECUTABLE ERLANG_INCLUDE_DIRS ERLANG_LIBRARIES
    VERSION_VAR ERLANG_VERSION
)

mark_as_advanced(ERL_EXECUTABLE ERLANG_INCLUDE_DIRS ERLANG_LIBRARIES) 