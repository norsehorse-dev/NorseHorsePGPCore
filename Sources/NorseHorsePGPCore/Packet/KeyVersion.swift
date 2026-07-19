// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation

// OpenPGP key version detection.
//
// Reads the version byte of the first key/subkey packet (tag 5/6/7/14) in a
// serialized key blob, so a consumer can route to the v4 or the v6 (RFC 9580)
// extractors without knowing the version in advance. A v4 key stream carries a
// version-4 primary and version-4 subkeys; a v6 key stream carries version-6
// throughout, so the first key packet's version is representative of the whole.
//
// Returns 4 or 6 for the two versions NorseHorsePGPCore supports, or nil if there is no
// key packet or the stream cannot be parsed. This is a read-only classification
// helper: it does not extract or decrypt any key material.
//
// Lives inside NorseHorsePGPCore, so it reaches the internal parsePackets/ParsedPacket
// directly; it is exposed public so cross-module consumers (e.g. CarrierPony)
// can branch on version before choosing an extractor.

public extension OpenPGPPacketParser {

    /// The OpenPGP version of the first key or subkey packet in `data`
    /// (4 for v4, 6 for RFC 9580 v6), or nil if none is found or parsing fails.
    ///
    /// - Parameter data: a serialized OpenPGP key stream (public or secret,
    ///   binary; dearmor first if the input is ASCII-armored).
    static func openPGPKeyVersion(from data: Data) -> Int? {
        guard let packets = try? parsePackets(data: Array(data)) else {
            return nil
        }
        // Secret/public primary (5/6) and secret/public subkey (7/14).
        let keyTags: Set<UInt8> = [5, 6, 7, 14]
        guard let keyPacket = packets.first(where: { keyTags.contains($0.tag) }),
              let versionByte = keyPacket.body.first else {
            return nil
        }
        return Int(versionByte)
    }
}
