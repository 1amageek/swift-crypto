##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(CryptoExtras
  "AES/AES_CBC.swift"
  "AES/AES_CFB.swift"
  "AES/AES_CTR.swift"
  "AES/AES_GCM_SIV.swift"
  "AES/Block Function.swift"
  "AES/BoringSSL/AES_CFB_boring.swift"
  "AES/BoringSSL/AES_CTR_boring.swift"
  "AES/BoringSSL/AES_GCM_SIV_boring.swift"
  "AES/CMAC.swift"
  "ARC/ARC+API.swift"
  "ARC/ARC.swift"
  "ARC/ARCCredential.swift"
  "ARC/ARCEncoding.swift"
  "ARC/ARCError.swift"
  "ARC/ARCPrecredential.swift"
  "ARC/ARCPresentation.swift"
  "ARC/ARCRepresentationLayout.swift"
  "ARC/ARCRepresentationReader.swift"
  "ARC/ARCRepresentationWriter.swift"
  "ARC/ARCRequest.swift"
  "ARC/ARCResponse.swift"
  "ARC/ARCServer.swift"
  "ChaCha20CTR/BoringSSL/ChaCha20CTR_boring.swift"
  "ChaCha20CTR/ChaCha20CTR.swift"
  "Digests/BoringSSL/SHA512256DigestContext.swift"
  "Digests/BoringSSL/SHA512256DigestOperations.swift"
  "Digests/SHA512256.swift"
  "Digests/SHA512256Digest.swift"
  "EC/Curve25519+PEM.swift"
  "EC/ObjectIdentifier.swift"
  "EC/PKCS8DERRepresentation.swift"
  "EC/PKCS8PrivateKey.swift"
  "EC/RFC8410AlgorithmIdentifier.swift"
  "ECToolbox/BoringSSL/ECToolbox_boring.swift"
  "ECToolbox/ECToolbox.swift"
  "H2G/HashToField.swift"
  "Key Derivation/KDF.swift"
  "Key Derivation/PBKDF2/BoringSSL/PBKDF2_boring.swift"
  "Key Derivation/PBKDF2/BoringSSL/PBKDF2_commoncrypto.swift"
  "Key Derivation/PBKDF2/PBKDF2.swift"
  "Key Derivation/Scrypt/BoringSSL/Scrypt_boring.swift"
  "Key Derivation/Scrypt/Scrypt.swift"
  "OPRFs/OPRF.swift"
  "OPRFs/OPRFClient.swift"
  "OPRFs/OPRFServer.swift"
  "OPRFs/VOPRF+API.swift"
  "OPRFs/VOPRFClient.swift"
  "OPRFs/VOPRFError.swift"
  "OPRFs/VOPRFServer.swift"
  "RSA/BoringSSLPassphraseCallbackManager.swift"
  "RSA/RSA+BlindSigning.swift"
  "RSA/RSA.swift"
  "RSA/RSA_boring.swift"
  "Util/BoringSSL/Zeroization_boring.swift"
  "Util/BoringSSLHelpers.swift"
  "Util/CryptoKitErrors_boring.swift"
  "Util/Data+Extensions.swift"
  "Util/DigestType.swift"
  "Util/Error.swift"
  "Util/I2OSP.swift"
  "Util/IntegerEncoding.swift"
  "Util/PEMDocument.swift"
  "Util/PrettyBytes.swift"
  "Util/SubjectPublicKeyInfo.swift"
  "ZKPs/DLEQ.swift"
  "ZKPs/Prover.swift"
  "ZKPs/Verifier.swift"
  "ZKPs/ZKPToolbox.swift"
)

target_include_directories(CryptoExtras PRIVATE
  $<TARGET_PROPERTY:CCryptoBoringSSL,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CCryptoBoringSSLShims,INCLUDE_DIRECTORIES>)

target_link_libraries(CryptoExtras PUBLIC
  ${SWIFT_CRYPTO_PLATFORM_LIBRARIES}
  Crypto
  CryptoBoringWrapper
  CCryptoBoringSSL
  CCryptoBoringSSLShims)

target_compile_options(CryptoExtras PRIVATE ${SWIFT_CRYPTO_COMPILE_OPTIONS})

if(APPLE)
  target_link_options(CryptoExtras PRIVATE
    "SHELL:-Xlinker -framework -Xlinker Security")
endif()

set_target_properties(CryptoExtras PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

set_property(GLOBAL APPEND PROPERTY SWIFT_CRYPTO_EXPORTS CryptoExtras)
