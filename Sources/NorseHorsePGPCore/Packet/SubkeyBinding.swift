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
// Android core's CPKeyTrust.isBound. Signatures are only ever verified under a
// primary key in the apps that use this, so there is no signing-subkey rule
// here.
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
