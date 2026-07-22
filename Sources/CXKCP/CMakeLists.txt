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

add_library(CXKCP STATIC
  "FIPS202-opt64/KeccakHash.c"
  "FIPS202-opt64/KeccakP-1600-opt64.c"
  "FIPS202-opt64/KeccakSponge.c"
  "FIPS202-opt64/SimpleFIPS202.c"
)

target_include_directories(CXKCP PUBLIC
  include)

target_compile_definitions(CXKCP PRIVATE
  $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>)
target_link_libraries(CXKCP PUBLIC
  ${SWIFT_CRYPTO_PLATFORM_LIBRARIES})
set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS CXKCP)
