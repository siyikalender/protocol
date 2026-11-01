# CMake build of the protocol library
#
# This is free and unencumbered software released into the public domain.
# For more information, please refer to <http://unlicense.org> and the
# LICENSE file in the root of this repository.
#
# Author: Claude Opus 5.5 <noreply@anthropic.com>
# Date:   2026
#
# The haluj and bit libraries are taken from targets haluj::haluj and
# bit::bit when the parent project has them, otherwise from the folders
# PROTOCOL_HALUJ_DIR and PROTOCOL_BIT_DIR (default: next to this one).

cmake_minimum_required(VERSION 3.14)

project(protocol LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(PROTOCOL_IS_TOP_LEVEL ON)
else()
  set(PROTOCOL_IS_TOP_LEVEL OFF)
endif()

option(PROTOCOL_BUILD_TESTS        "Build the protocol tests"            ${PROTOCOL_IS_TOP_LEVEL})
option(PROTOCOL_WARNINGS_AS_ERRORS "Treat warnings in tests as errors"   OFF)

set(PROTOCOL_HALUJ_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../haluj" CACHE PATH "haluj source folder")
set(PROTOCOL_BIT_DIR   "${CMAKE_CURRENT_SOURCE_DIR}/../bit"   CACHE PATH "bit source folder")

if(NOT TARGET haluj::haluj)
  set(HALUJ_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(HALUJ_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  add_subdirectory(${PROTOCOL_HALUJ_DIR} ${CMAKE_BINARY_DIR}/_deps/haluj)
endif()

if(NOT TARGET bit::bit)
  set(BIT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(BIT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(BIT_INSTALL OFF CACHE BOOL "" FORCE)
  add_subdirectory(${PROTOCOL_BIT_DIR} ${CMAKE_BINARY_DIR}/_deps/bit)
endif()

# IPv4 stack: protocol::ipv4
add_library(protocol_ipv4 STATIC src/protocol/ipv4/stack.cpp)
add_library(protocol::ipv4 ALIAS protocol_ipv4)

target_include_directories(protocol_ipv4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(protocol_ipv4 PUBLIC haluj::haluj bit::bit)
target_compile_features(protocol_ipv4 PUBLIC cxx_std_20)

if(PROTOCOL_BUILD_TESTS)
  add_library(protocol_warnings INTERFACE)

  if(MSVC)
    target_compile_options(protocol_warnings INTERFACE /W4 /permissive-)
    if(PROTOCOL_WARNINGS_AS_ERRORS)
      target_compile_options(protocol_warnings INTERFACE /WX)
    endif()
  else()
    target_compile_options(protocol_warnings INTERFACE -Wall -Wextra -Wpedantic)
    if(PROTOCOL_WARNINGS_AS_ERRORS)
      target_compile_options(protocol_warnings INTERFACE -Werror)
    endif()
  endif()

  enable_testing()
  add_subdirectory(tests)
endif()
