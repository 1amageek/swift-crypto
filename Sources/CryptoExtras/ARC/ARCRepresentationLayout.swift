#if !hasFeature(Embedded)
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

extension ARC {
    struct RepresentationLayout<H2G: HashToGroup> {
        let byteCount: Int

        init(pointCount: Int, scalarCount: Int) throws {
            guard pointCount >= 0, scalarCount >= 0 else {
                throw ARC.Errors.internalFailure
            }

            let pointBytes = pointCount.multipliedReportingOverflow(
                by: H2G.G.Element.oprfRepresentationByteCount
            )
            let scalarBytes = scalarCount.multipliedReportingOverflow(
                by: H2G.G.Scalar.rawRepresentationByteCount
            )
            let totalBytes = pointBytes.partialValue.addingReportingOverflow(
                scalarBytes.partialValue
            )
            guard
                !pointBytes.overflow,
                !scalarBytes.overflow,
                !totalBytes.overflow
            else {
                throw ARC.Errors.internalFailure
            }
            self.byteCount = totalBytes.partialValue
        }
    }
}

#endif  // !hasFeature(Embedded)
