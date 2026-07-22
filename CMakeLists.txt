##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

cmake_minimum_required(VERSION 3.29)

set(CMAKE_Swift_LANGUAGE_VERSION 6)

project(SwiftCrypto
  LANGUAGES ASM C CXX Swift)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

include(SwiftSupport)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

set(SWIFT_CRYPTO_COMPILE_OPTIONS
    -package-name com.apple.swift-crypto
    -enable-experimental-feature Lifetimes
)

option(BUILD_SHARED_LIBS "Build shared libraries by default" YES)

if(BUILD_SHARED_LIBS)
  set(CMAKE_POSITION_INDEPENDENT_CODE YES)
endif()

if(APPLE AND NOT CMAKE_CROSSCOMPILING)
  set(CMAKE_AR "/usr/bin/ar")
  set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> crs <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_RANLIB "/usr/bin/ranlib")
endif()

set(CMAKE_CXX_STANDARD 17)
if(CMAKE_SYSTEM_NAME STREQUAL Windows)
  # We need to ensure that we don't include the min/max macros from the Windows SDK.
  add_compile_definitions(NOMINMAX)
  # We can only link against the DLL version of the MSVC runtime library for now.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  # We need to set the static library prefix to "lib" so that we can link against the static libraries.
  set(CMAKE_STATIC_LIBRARY_PREFIX_Swift "lib")
endif()

set(SWIFT_CRYPTO_PLATFORM_LIBRARIES)
if(NOT APPLE)
  find_package(dispatch CONFIG QUIET)
  find_package(Foundation CONFIG QUIET)
  if(TARGET dispatch)
    list(APPEND SWIFT_CRYPTO_PLATFORM_LIBRARIES dispatch)
  endif()
  if(TARGET Foundation)
    list(APPEND SWIFT_CRYPTO_PLATFORM_LIBRARIES Foundation)
  endif()
endif()

include(FetchContent)
find_package(SwiftASN1 CONFIG)
if(NOT SwiftASN1_FOUND)
  message("-- Vending swift-asn1")
  FetchContent_Declare(ASN1
    GIT_REPOSITORY https://github.com/1amageek/swift-asn1.git
    GIT_TAG b6ceb273cb9c35b7a44f853ddd9e6e5044938102)
  FetchContent_MakeAvailable(ASN1)
endif()

add_subdirectory(Sources)
add_subdirectory(cmake/modules)
