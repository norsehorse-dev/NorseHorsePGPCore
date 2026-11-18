// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// SubkeyBinding.swift
// NorseHorsePGPCore
//
// Whether a subkey really belongs to the key it travels with.
//
// A contact is pinned by the fingerprint of their PRIMARY key. The key that
// carries it also carries subkeys, and nothing checks a subkey's binding
// signature when the key is parsed. Without a check, a key with the right
// primary and someone else's subkey would be accepted: the fingerprint still
// matches, and messages would be encrypted to a key the contact does not hold.
// Whoever hands out contact keys could do that.
//
// A subkey is accepted only when the primary key has signed a subkey binding
// (type 0x18) over it and has not revoked it (type 0x28). The same rule as the
// Android core's CPKeyTrust.isBound.
//
// A signing subkey needs more. An identity imported from another app can sign
// with a subkey, and a signature from that subkey speaks for the identity. So
// the subkey must also have signed the primary key back (a primary key binding,
// type 0x19, embedded in the subkey binding). Without it, someone could bind
// another person's signing subkey to their own key and take credit for that
// person's signatures. `isBoundSigner` is that rule, the same as the Android
// core's CPKeyTrust.isBoundSigner.
//
// Only Ed25519 primaries are handled (v4 EdDSA and v6 Ed25519). A key with any
// other primary is reported as not bound.

import Foundation

public extension OpenPGPPacketParser {

    /// True when the encryption subkey in `recipient` is bound to, and not
    /// revoked by, the primary key of the transferable public key `data`.
    static func isBound(_ recipient: Cv25519Recipient, inPublicKey data: Data) -> Bool {
        isBound(subkeyFingerprint: recipient.subkeyFingerprint, inPublicKey: data)
    }

    /// True when the ML-KEM-768 + X25519 subkey in `recipient` is bound to, and
    /// not revoked by, the primary key of the transferable public key `data`.
    static func isBound(_ recipient: CompositeKEMRecipient, inPublicKey data: Data) -> Bool {
        isBound(subkeyFingerprint: recipient.subkeyFingerprint, inPublicKey: data)
    }

    /// True when `subkeyFingerprint` names a subkey of the transferable public
    /// key `data` (binary, not armored) that the primary key has bound and not
    /// revoked. False for anything else, including a key that does not parse.
    static func isBound(subkeyFingerprint: [UInt8], inPublicKey data: Data) -> Bool {
        isBound(subkeyFingerprint: subkeyFingerprint, inPublicKey: data, asSigner: false)
    }

    /// True when `subkeyFingerprint` names a subkey of `data` that may sign for
    /// the key: bound by the primary key, not revoked, and carrying a valid
    /// signature of its own over the primary key. Use this before trusting a
    /// signature made by a subkey.
    static func isBoundSigner(subkeyFingerprint: [UInt8], inPublicKey data: Data) -> Bool {
        isBound(subkeyFingerprint: subkeyFingerprint, inPublicKey: data, asSigner: true)
    }

    /// The fingerprint of every key in the transferable public key `data`,
    /// primary first. Empty when the data does not parse. A receiver uses this
    /// to find whose signing subkey made a signature.
    static func keyFingerprints(inPublicKey data: Data) -> [[UInt8]] {
        guard let packets = try? parsePackets(data: Array(data)) else { return [] }
        return packets.compactMap { packet in
            guard packet.tag == 6 || packet.tag == 14,
                  let version = packet.body.first, version == 4 || version == 6 else { return nil }
            return fingerprint(ofKeyBody: packet.body, version: version)
        }
    }

    /// The 32-byte Ed25519 public key of the key in `data` that has
    /// `keyFingerprint`, primary or subkey. Throws when there is no such key or
    /// it is not Ed25519.
    static func ed25519PublicKey(fromPublicKeyData data: Data, keyFingerprint: [UInt8]) throws -> [UInt8] {
        let packets = try parsePackets(data: Array(data))
        for packet in packets where packet.tag == 6 || packet.tag == 14 {
            guard let version = packet.body.first, version == 4 || version == 6,
                  fingerprint(ofKeyBody: packet.body, version: version) == keyFingerprint else { continue }
            guard let raw = ed25519Raw(fromKeyBody: packet.body) else { break }
            return raw
        }
        throw PacketParserError.invalidPacket("No Ed25519 key with that fingerprint")
    }

    /// The raw Ed25519 public key in a key packet body: v6 algorithm 27 (32 raw
    /// bytes) or v4 algorithm 22 (curve OID, then an MPI with an optional 0x40
    /// prefix). Nil for anything else.
    private static func ed25519Raw(fromKeyBody body: [UInt8]) -> [UInt8]? {
        guard body.count > 6 else { return nil }
        if body[0] == 6 {
            guard body[5] == 27, body.count >= 10 + 32,
                  (Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])) == 32 else { return nil }
            return Array(body[10..<42])
        }
        guard body[0] == 4, body[5] == 22 else { return nil }
        var off = 6
        let oidLength = Int(body[off]); off += 1
        off += oidLength
        guard off + 2 <= body.count else { return nil }
        let bits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        let count = (bits + 7) / 8
        guard off + count <= body.count else { return nil }
        var raw = Array(body[off..<(off + count)])
        if raw.first == 0x40 { raw = Array(raw.dropFirst()) }
        return raw.count == 32 ? raw : nil
    }

    private static func isBound(subkeyFingerprint: [UInt8], inPublicKey data: Data, asSigner: Bool) -> Bool {
        guard let packets = try? parsePackets(data: Array(data)),
              let primary = packets.first, primary.tag == 6,
              let version = primary.body.first, version == 4 || version == 6,
              let primaryKey = try? ed25519PublicKey(fromPublicKeyData: data) else {
            return false
        }

        var bound = false
        var index = 1
        while index < packets.count {
            guard packets[index].tag == 14 else { index += 1; continue }
            let subkey = packets[index]
            index += 1
            // The signatures that belong to a subkey are the ones directly after it.
            var signatures: [ParsedPacket] = []
            while index < packets.count, packets[index].tag == 2 {
                signatures.append(packets[index])
                index += 1
            }
            guard subkey.body.first == version,
                  fingerprint(ofKeyBody: subkey.body, version: version) == subkeyFingerprint else {
                continue
            }
            let document = hashFraming(ofKeyBody: primary.body, version: version)
                + hashFraming(ofKeyBody: subkey.body, version: version)
            for packet in signatures {
                guard let signature = try? parseSignaturePacket(body: packet.body),
                      signature.version == version,
                      signature.signatureType == 0x18 || signature.signatureType == 0x28,
                      (try? verifyEd25519Signature(signature: signature, document: document, publicKey: primaryKey)) == true else {
                    continue
                }
                // A valid revocation settles it, wherever it sits and however
                // many valid bindings there are.
                if signature.signatureType == 0x28 { return false }
                if asSigner {
                    // The subkey has to have signed the primary key back.
                    guard let subkeyKey = ed25519Raw(fromKeyBody: subkey.body) else { continue }
                    let backSigned = (signature.hashedSubpackets + signature.unhashedSubpackets).contains { subpacket in
                        guard subpacket.type == 32,
                              let back = try? parseSignaturePacket(body: subpacket.data),
                              back.version == version, back.signatureType == 0x19 else { return false }
                        return (try? verifyEd25519Signature(signature: back, document: document, publicKey: subkeyKey)) == true
                    }
                    guard backSigned else { continue }
                }
                bound = true
            }
        }
        return bound
    }

    private static func fingerprint(ofKeyBody body: [UInt8], version: UInt8) -> [UInt8] {
        version == 6 ? computeV6Fingerprint(packetBody: body) : computeV4Fingerprint(packetBody: body)
    }

    /// A key as it enters a signature hash: 0x99 and a two-octet length for
    /// v4, 0x9B and a four-octet length for v6, then the key packet body.
    private static func hashFraming(ofKeyBody body: [UInt8], version: UInt8) -> [UInt8] {
        let n = body.count
        var out: [UInt8] = version == 6
            ? [0x9B, UInt8((n >> 24) & 0xFF), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
            : [0x99, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
        out.append(contentsOf: body)
        return out
    }
}
