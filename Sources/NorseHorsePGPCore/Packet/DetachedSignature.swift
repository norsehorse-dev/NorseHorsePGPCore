import Foundation
import CryptoKit

// Detached Ed25519 (v4) signature builder.
//
// Produces an armored OpenPGP detached signature over arbitrary bytes, given an
// already-extracted Ed25519SigningInfo. This is the relay-challenge signing path
// for CarrierPony (sign the nonce, send the armored signature) and a general
// detached-sign primitive for the portfolio.
//
// Ported from the app's signDetachedEd25519v4, decoupled to take the signing
// info directly. Self-contained: it carries its own small OpenPGP encoders
// (subpacket, MPI, new-format packet, armor/CRC24) so it doesn't depend on the
// builder's private helpers. The output is RFC-conformant and the conformance
// bar is gpg 2.4.4 verifying it.
//
// Requires Ed25519SigningInfo and PacketBuilderError to be public (spec Part A).

public extension OpenPGPPacketBuilder {

    /// Build an armored OpenPGP v4 detached signature over `data` using the
    /// Ed25519 key in `signingInfo`. `isText` selects signature type 0x01 (text,
    /// CRLF-canonicalized) vs 0x00 (binary). CarrierPony uses binary.
    static func detachedSignatureEd25519(
        over data: Data,
        signingInfo: Ed25519SigningInfo,
        isText: Bool = false
    ) throws -> String {

        let sigType: UInt8 = isText ? 0x01 : 0x00
        let algoEdDSALegacy: UInt8 = 22
        let hashSHA256: UInt8 = 8

        let documentBytes: [UInt8] = isText ? detachedCanonicalize(Array(data)) : Array(data)

        // ---- Hashed subpackets: creation time (2), issuer fingerprint (33) ----
        let now = UInt32(Date().timeIntervalSince1970)
        var hashedSubpackets: [UInt8] = []
        hashedSubpackets.append(contentsOf: detachedSubpacket(type: 2, data: [
            UInt8((now >> 24) & 0xFF), UInt8((now >> 16) & 0xFF),
            UInt8((now >> 8) & 0xFF),  UInt8(now & 0xFF)
        ]))

        let v4FP: [UInt8] = signingInfo.fingerprint.count >= 20
            ? Array(signingInfo.fingerprint.suffix(20))
            : signingInfo.fingerprint
        var fpData: [UInt8] = [4]
        fpData.append(contentsOf: v4FP)
        hashedSubpackets.append(contentsOf: detachedSubpacket(type: 33, data: fpData))

        // ---- Unhashed subpackets: issuer key ID (16) ----
        var unhashedSubpackets: [UInt8] = []
        unhashedSubpackets.append(contentsOf: detachedSubpacket(type: 16, data: signingInfo.keyID))

        // ---- Hash input (v4) ----
        var hashInput = Data(documentBytes)
        var trailer: [UInt8] = [4, sigType, algoEdDSALegacy, hashSHA256]
        let hashedLen16 = UInt16(hashedSubpackets.count)
        trailer.append(UInt8((hashedLen16 >> 8) & 0xFF))
        trailer.append(UInt8(hashedLen16 & 0xFF))
        trailer.append(contentsOf: hashedSubpackets)
        hashInput.append(contentsOf: trailer)

        // v4 final trailer: 0x04 0xFF || 4-byte BE hashed length
        let totalHashed4 = UInt32(trailer.count)
        hashInput.append(4)
        hashInput.append(0xFF)
        hashInput.append(UInt8((totalHashed4 >> 24) & 0xFF))
        hashInput.append(UInt8((totalHashed4 >> 16) & 0xFF))
        hashInput.append(UInt8((totalHashed4 >> 8) & 0xFF))
        hashInput.append(UInt8(totalHashed4 & 0xFF))

        let digest = Array(SHA256.hash(data: hashInput))

        // ---- Sign digest with Ed25519 ----
        let rawSig = Array(try signingInfo.privateKey.signature(for: Data(digest)))
        guard rawSig.count == 64 else {
            throw PacketBuilderError.signingFailed("Ed25519 signature is \(rawSig.count) bytes, expected 64")
        }

        // ---- Assemble v4 signature packet body ----
        var sigBody: [UInt8] = [4, sigType, algoEdDSALegacy, hashSHA256]
        sigBody.append(UInt8((hashedLen16 >> 8) & 0xFF))
        sigBody.append(UInt8(hashedLen16 & 0xFF))
        sigBody.append(contentsOf: hashedSubpackets)

        let unhashedLen16 = UInt16(unhashedSubpackets.count)
        sigBody.append(UInt8((unhashedLen16 >> 8) & 0xFF))
        sigBody.append(UInt8(unhashedLen16 & 0xFF))
        sigBody.append(contentsOf: unhashedSubpackets)

        sigBody.append(digest[0])
        sigBody.append(digest[1])

        // EdDSA v4 signature: two MPIs (R, S)
        sigBody.append(contentsOf: detachedMPI(Array(rawSig[0..<32])))
        sigBody.append(contentsOf: detachedMPI(Array(rawSig[32..<64])))

        let packet = detachedNewFormatPacket(tag: 2, body: sigBody)
        return detachedArmor(Data(packet))
    }

    // MARK: - Local OpenPGP encoders

    private static func detachedSubpacket(type: UInt8, data: [UInt8]) -> [UInt8] {
        let length = data.count + 1   // +1 for the type octet
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

    /// Standard OpenPGP MPI: 2-byte bit length + minimal big-endian bytes.
    private static func detachedMPI(_ bytes: [UInt8]) -> [UInt8] {
        var b = bytes
        while b.first == 0 { b.removeFirst() }
        if b.isEmpty { return [0, 0] }
        var bitLen = (b.count - 1) * 8
        var v = b[0]
        var hi = 8
        while (v & 0x80) == 0 && hi > 0 { v <<= 1; hi -= 1 }
        bitLen += hi
        var out: [UInt8] = [UInt8((bitLen >> 8) & 0xFF), UInt8(bitLen & 0xFF)]
        out.append(contentsOf: b)
        return out
    }

    private static func detachedNewFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
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

    private static func detachedArmor(_ packet: Data) -> String {
        let b64 = packet.base64EncodedString()
        var lines: [String] = []
        var i = b64.startIndex
        while i < b64.endIndex {
            let j = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[i..<j]))
            i = j
        }
        let crc = detachedCRC24(Array(packet))
        let crcB64 = Data(crc).base64EncodedString()
        var out = "-----BEGIN PGP SIGNATURE-----\n\n"
        out += lines.joined(separator: "\n")
        out += "\n=" + crcB64 + "\n"
        out += "-----END PGP SIGNATURE-----\n"
        return out
    }

    private static func detachedCRC24(_ data: [UInt8]) -> [UInt8] {
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

    /// CRLF line-ending normalization for text-mode (0x01) signatures.
    private static func detachedCanonicalize(_ bytes: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var i = 0
        while i < bytes.count {
            let b = bytes[i]
            if b == 0x0D {                       // CR (or CRLF)
                out.append(0x0D); out.append(0x0A)
                if i + 1 < bytes.count && bytes[i + 1] == 0x0A { i += 1 }
            } else if b == 0x0A {                // lone LF
                out.append(0x0D); out.append(0x0A)
            } else {
                out.append(b)
            }
            i += 1
        }
        return out
    }
}
