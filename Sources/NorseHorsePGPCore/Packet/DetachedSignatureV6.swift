// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import Foundation
import CryptoKit

// Detached Ed25519 (v6 / RFC 9580) signature builder and verifier.
//
// The v4 counterpart lives in DetachedSignature.swift; this is the v6 path, used
// for the CarrierPony relay challenge when the identity is a v6 key. A v6 key
// signs with a version-6 signature packet (algorithm 27, native 64-byte Ed25519
// signature, salted hash), which gpg 2.4.4 cannot verify but any RFC 9580
// implementation (Sequoia, gpg 2.5+) can.
//
// The builder mirrors the shipped inline v6 signer (buildBinarySignaturePacketV6)
// exactly: same hashed-subpacket set, same issuer-fingerprint (type 33, v6 form
// 0x06 || 32-byte fp), same hash input
//   salt || document || rawHashedPortion || 0x06 0xFF || 4-byte BE len(rawHashedPortion)
// where rawHashedPortion = version(6) | sigType(0x00) | pubAlgo(27) | hashAlgo |
//   hashedLen(4 BE) | hashedSubpackets. It uses SHA-256 with a 16-byte salt, the
// same choice as the inline path.
//
// The verifier is deliberately hash-agile: it reads the hash algorithm and salt
// from the packet, so it accepts SHA-256/16-salt signatures (this builder, the
// inline path) AND SHA-512/32-salt signatures (Sequoia's default), which is what
// a relay verifying arbitrary v6 clients requires.
//
// Requires Ed25519SigningInfo and PacketBuilderError to be public (spec Part A).

public extension OpenPGPPacketBuilder {

    /// Build an armored OpenPGP v6 detached signature (type 0x00, binary) over
    /// `data` using the Ed25519 key in `signingInfo`. The signingInfo fingerprint
    /// must be the 32-byte v6 fingerprint of the signing (sub)key.
    static func detachedSignatureEd25519V6(
        over data: Data,
        signingInfo: Ed25519SigningInfo
    ) throws -> String {

        let sigType: UInt8 = 0x00
        let pubAlgoEd25519: UInt8 = 27   // RFC 9580 Ed25519
        let hashSHA256: UInt8 = 8
        let v6FP = Array(signingInfo.fingerprint.prefix(32))
        guard v6FP.count == 32 else {
            throw PacketBuilderError.signingFailed("v6 detached signature requires a 32-byte fingerprint")
        }

        // 16-byte salt for SHA-256 (RFC 9580 salt size table).
        var salt = [UInt8](repeating: 0, count: 16)
        for i in salt.indices { salt[i] = UInt8.random(in: 0...255) }

        // Hashed subpackets: creation time (2), issuer fingerprint (33, v6 = 0x06||fp).
        let now = UInt32(Date().timeIntervalSince1970)
        var hashedSubpackets: [UInt8] = []
        hashedSubpackets.append(contentsOf: v6DetachedSubpacket(type: 2, data: [
            UInt8((now >> 24) & 0xFF), UInt8((now >> 16) & 0xFF),
            UInt8((now >> 8) & 0xFF),  UInt8(now & 0xFF)
        ]))
        var fpData: [UInt8] = [6]
        fpData.append(contentsOf: v6FP)
        hashedSubpackets.append(contentsOf: v6DetachedSubpacket(type: 33, data: fpData))

        // Unhashed subpackets: issuer key ID (16) = leading 8 of the v6 fingerprint.
        var unhashedSubpackets: [UInt8] = []
        unhashedSubpackets.append(contentsOf: v6DetachedSubpacket(type: 16, data: Array(v6FP.prefix(8))))

        // rawHashedPortion: 6 | sigType | 27 | hash | hashedLen(4 BE) | hashed
        let hashedLen32 = UInt32(hashedSubpackets.count)
        var rawHashedPortion: [UInt8] = [6, sigType, pubAlgoEd25519, hashSHA256]
        rawHashedPortion.append(UInt8((hashedLen32 >> 24) & 0xFF))
        rawHashedPortion.append(UInt8((hashedLen32 >> 16) & 0xFF))
        rawHashedPortion.append(UInt8((hashedLen32 >> 8) & 0xFF))
        rawHashedPortion.append(UInt8(hashedLen32 & 0xFF))
        rawHashedPortion.append(contentsOf: hashedSubpackets)

        // Hash input (v6): salt || document || rawHashedPortion || 0x06 0xFF || 4-byte BE total
        var hashInput = Data()
        hashInput.append(contentsOf: salt)
        hashInput.append(data)
        hashInput.append(contentsOf: rawHashedPortion)
        let totalHashed4 = UInt32(rawHashedPortion.count)
        hashInput.append(0x06)
        hashInput.append(0xFF)
        hashInput.append(UInt8((totalHashed4 >> 24) & 0xFF))
        hashInput.append(UInt8((totalHashed4 >> 16) & 0xFF))
        hashInput.append(UInt8((totalHashed4 >> 8) & 0xFF))
        hashInput.append(UInt8(totalHashed4 & 0xFF))

        let digest = Array(SHA256.hash(data: hashInput))

        let rawSig = Array(try signingInfo.privateKey.signature(for: Data(digest)))
        guard rawSig.count == 64 else {
            throw PacketBuilderError.signingFailed("v6 Ed25519 signature must be 64 bytes, got \(rawSig.count)")
        }

        // Packet body: 6 | sigType | 27 | hash | hashedLen(4) | hashed |
        //   unhashedLen(4) | unhashed | hashPrefix(2) | saltLen(1) | salt | sig(64)
        var sigBody: [UInt8] = [6, sigType, pubAlgoEd25519, hashSHA256]
        sigBody.append(UInt8((hashedLen32 >> 24) & 0xFF))
        sigBody.append(UInt8((hashedLen32 >> 16) & 0xFF))
        sigBody.append(UInt8((hashedLen32 >> 8) & 0xFF))
        sigBody.append(UInt8(hashedLen32 & 0xFF))
        sigBody.append(contentsOf: hashedSubpackets)
        let unhashedLen32 = UInt32(unhashedSubpackets.count)
        sigBody.append(UInt8((unhashedLen32 >> 24) & 0xFF))
        sigBody.append(UInt8((unhashedLen32 >> 16) & 0xFF))
        sigBody.append(UInt8((unhashedLen32 >> 8) & 0xFF))
        sigBody.append(UInt8(unhashedLen32 & 0xFF))
        sigBody.append(contentsOf: unhashedSubpackets)
        sigBody.append(digest[0])
        sigBody.append(digest[1])
        sigBody.append(UInt8(salt.count))
        sigBody.append(contentsOf: salt)
        sigBody.append(contentsOf: rawSig)   // native 64-byte Ed25519 sig (no MPI)

        let packet = v6DetachedNewFormatPacket(tag: 2, body: sigBody)
        return v6DetachedArmor(Data(packet))
    }

    // MARK: - Local OpenPGP encoders (file-scoped; distinct names from the v4 file)

    private static func v6DetachedSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        let length = data.count + 1
        var out: [UInt8] = []
        if length < 192 {
            out.append(UInt8(length))
        } else if length < 8384 {
            let l = length - 192
            out.append(UInt8((l >> 8) + 192))
            out.append(UInt8(l & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((length >> 24) & 0xFF))
            out.append(UInt8((length >> 16) & 0xFF))
            out.append(UInt8((length >> 8) & 0xFF))
            out.append(UInt8(length & 0xFF))
        }
        out.append(type)
        out.append(contentsOf: data)
        return out
    }

    private static func v6DetachedNewFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0xC0 | tag]
        let len = body.count
        if len < 192 {
            out.append(UInt8(len))
        } else if len < 8384 {
            let l = len - 192
            out.append(UInt8((l >> 8) + 192))
            out.append(UInt8(l & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((len >> 24) & 0xFF))
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(contentsOf: body)
        return out
    }

    private static func v6DetachedArmor(_ packet: Data) -> String {
        let b64 = packet.base64EncodedString()
        var lines: [String] = []
        var i = b64.startIndex
        while i < b64.endIndex {
            let j = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[i..<j]))
            i = j
        }
        let crc = v6DetachedCRC24(Array(packet))
        let crcB64 = Data(crc).base64EncodedString()
        var out = "-----BEGIN PGP SIGNATURE-----\n\n"
        out += lines.joined(separator: "\n")
        out += "\n=" + crcB64 + "\n"
        out += "-----END PGP SIGNATURE-----\n"
        return out
    }

    private static func v6DetachedCRC24(_ data: [UInt8]) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if (crc & 0x1000000) != 0 { crc ^= 0x1864CFB }
            }
        }
        crc &= 0xFFFFFF
        return [UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)]
    }
}

public extension OpenPGPPacketParser {

    /// Verify an armored OpenPGP v6 detached signature (`armored`) over `document`
    /// using the signer's 32-byte Ed25519 v6 public key. Hash-agile: reads the
    /// hash algorithm (SHA-256/384/512) and salt from the packet, so it accepts
    /// both this core's SHA-256 signatures and Sequoia's SHA-512 signatures.
    /// Returns true on a cryptographically valid signature, false otherwise.
    static func verifyDetachedSignatureEd25519V6(
        armored: String,
        over document: Data,
        signerV6PublicKey: [UInt8]
    ) throws -> Bool {

        guard signerV6PublicKey.count == 32 else { return false }

        // Dearmor: keep only the base64 body lines (drop header/footer/CRC).
        let bodyB64 = armored
            .split(separator: "\n", omittingEmptySubsequences: true)
            .filter { !$0.hasPrefix("-----") && !$0.hasPrefix("=") }
            .joined()
        guard let packet = Data(base64Encoded: bodyB64) else { return false }
        let bytes = Array(packet)
        guard bytes.count > 2, (bytes[0] & 0x3F) == 2 else { return false }

        // New-format length header.
        var i = 1
        let o = Int(bytes[i]); i += 1
        let bodyLen: Int
        if o < 192 {
            bodyLen = o
        } else if o < 224 {
            guard i < bytes.count else { return false }
            bodyLen = ((o - 192) << 8) + Int(bytes[i]) + 192; i += 1
        } else if o == 255 {
            guard i + 4 <= bytes.count else { return false }
            bodyLen = (Int(bytes[i]) << 24) | (Int(bytes[i+1]) << 16) | (Int(bytes[i+2]) << 8) | Int(bytes[i+3]); i += 4
        } else {
            return false
        }
        guard i + bodyLen <= bytes.count else { return false }
        let body = Array(bytes[i..<(i + bodyLen)])

        // Parse v6 signature body.
        guard body.count > 8, body[0] == 6 else { return false }
        let sigType = body[1]
        let pubAlgo = body[2]
        let hashAlgo = body[3]
        guard pubAlgo == 27 else { return false }   // Ed25519
        var p = 4
        let hashedLen = (Int(body[p]) << 24) | (Int(body[p+1]) << 16) | (Int(body[p+2]) << 8) | Int(body[p+3]); p += 4
        guard p + hashedLen <= body.count else { return false }
        let hashed = Array(body[p..<(p + hashedLen)]); p += hashedLen
        guard p + 4 <= body.count else { return false }
        let unhashedLen = (Int(body[p]) << 24) | (Int(body[p+1]) << 16) | (Int(body[p+2]) << 8) | Int(body[p+3]); p += 4
        guard p + unhashedLen + 2 + 1 <= body.count else { return false }
        p += unhashedLen                              // skip unhashed
        let prefix = Array(body[p..<(p + 2)]); p += 2
        let saltLen = Int(body[p]); p += 1
        guard p + saltLen + 64 <= body.count else { return false }
        let salt = Array(body[p..<(p + saltLen)]); p += saltLen
        let sig = Array(body[p..<(p + 64)])

        // Reconstruct rawHashedPortion and the v6 hash input.
        var rawHashedPortion: [UInt8] = [6, sigType, pubAlgo, hashAlgo]
        rawHashedPortion.append(UInt8((UInt32(hashedLen) >> 24) & 0xFF))
        rawHashedPortion.append(UInt8((UInt32(hashedLen) >> 16) & 0xFF))
        rawHashedPortion.append(UInt8((UInt32(hashedLen) >> 8) & 0xFF))
        rawHashedPortion.append(UInt8(UInt32(hashedLen) & 0xFF))
        rawHashedPortion.append(contentsOf: hashed)

        var hashInput = Data()
        hashInput.append(contentsOf: salt)
        hashInput.append(document)
        hashInput.append(contentsOf: rawHashedPortion)
        let total = UInt32(rawHashedPortion.count)
        hashInput.append(0x06)
        hashInput.append(0xFF)
        hashInput.append(UInt8((total >> 24) & 0xFF))
        hashInput.append(UInt8((total >> 16) & 0xFF))
        hashInput.append(UInt8((total >> 8) & 0xFF))
        hashInput.append(UInt8(total & 0xFF))

        let digest: [UInt8]
        switch hashAlgo {
        case 8:  digest = Array(SHA256.hash(data: hashInput))
        case 9:  digest = Array(SHA384.hash(data: hashInput))
        case 10: digest = Array(SHA512.hash(data: hashInput))
        default: return false
        }
        // Left 2 octets of the hash must match the stored prefix.
        guard digest.count >= 2, digest[0] == prefix[0], digest[1] == prefix[1] else { return false }

        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(signerV6PublicKey)) else {
            return false
        }
        return pub.isValidSignature(Data(sig), for: Data(digest))
    }
}
