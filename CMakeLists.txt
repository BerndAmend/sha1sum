cmake_minimum_required(VERSION 3.8)

project(sha1sum)
enable_testing()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
        -Wall -Wextra -Wno-unknown-pragmas -Wwrite-strings -Wenum-compare
        -Wno-conversion-null -Werror=return-type
        -Wnon-virtual-dtor
        -Woverloaded-virtual
        $<$<VERSION_GREATER_EQUAL:$<CXX_COMPILER_VERSION>,5.0>:-pedantic>
        $<$<VERSION_GREATER_EQUAL:$<CXX_COMPILER_VERSION>,4.9>:-fstack-protector-strong>
        $<$<VERSION_LESS:$<CXX_COMPILER_VERSION>,5.0>:-Wno-missing-field-initializers>
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/W4)
endif()

option(SHA1SUM_ENABLE_CLANG_TIDY "" ON)
if(SHA1SUM_ENABLE_CLANG_TIDY)
    find_program(
        CLANG_TIDY_EXE
        NAMES "clang-tidy"
        DOC "Path to clang-tidy executable"
        )
    if(CLANG_TIDY_EXE)
        message(STATUS "Enable clang-tidy: ${CLANG_TIDY_EXE}")
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}" "-fix" "-checks=*,-cppcoreguidelines-pro-bounds-*,-cppcoreguidelines-pro-type-vararg,-google-build-using-namespace")
    endif()
endif()

add_executable(sha1sum main.cpp SHA1Sum.h)
add_test(sha1sum sha1sum)
