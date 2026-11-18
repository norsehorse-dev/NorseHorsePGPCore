// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse
//
// RFC 9580 (v6) key extraction. Companion to the v4-only KeyExtraction.swift.
//
// v6 differences this file accounts for:
//   • Native algorithms: 27 = Ed25519, 25 = X25519 (no OID, no MPI wrapping)
//   • Public key body: version(1)=6 | ctime(4) | algo(1) | matLen(4 BE) | material
//   • Secret material (unprotected, S2K usage 0): raw 32 bytes, NO checksum
//     (RFC 9580 §5.5.3) — and for X25519 the scalar is already native
//     little-endian, so it is used as-is (no big-endian reversal like v4 Cv25519)
//   • Fingerprint: SHA-256(0x9B | 4-byte BE body length | body); key ID = first 8
//   • Data signatures live on the Ed25519 SIGNING SUBKEY (tag 7 / 14, algo 27);
//     the v6 primary is typically certify-only, so signing extraction targets the
//     subkey and falls back to a signing-capable primary only if no subkey exists.

import Foundation
import CryptoKit

public extension OpenPGPPacketParser {

    /// v6 Ed25519 signing key from a transferable secret key. Targets the Ed25519
    /// signing subkey (tag 7, algo 27); falls back to a v6 Ed25519 primary (tag 5).
    static func ed25519SigningInfo(fromV6SecretKey data: Data, passphrase: String? = nil) throws -> Ed25519SigningInfo {
        let packets = try parsePackets(data: Array(data))
        let pkt = packets.first(where: { $0.tag == 7 && v6AlgorithmByte($0.body) == 27 })
               ?? packets.first(where: { $0.tag == 5 && v6AlgorithmByte($0.body) == 27 })
        guard let secret = pkt, let pub = v6PublicPortion(body: secret.body) else {
            throw PacketParserError.invalidPacket("No v6 Ed25519 signing key found")
        }
        let seed = try v6SecretMaterial(body: secret.body, publicEnd: pub.end, packetTag: secret.tag, passphrase: passphrase)
        guard seed.count == 32 else {
            throw PacketParserError.invalidPacket("v6 Ed25519 seed must be 32 bytes, got \(seed.count)")
        }
        let fingerprint = computeV6Fingerprint(packetBody: pub.publicBody)
        let keyID = Array(fingerprint.prefix(8))
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return Ed25519SigningInfo(privateKey: signingKey, keyID: keyID, fingerprint: fingerprint)
    }

    /// v6 X25519 decryption key from a transferable secret key (tag 7, algo 25).
    static func x25519DecryptionKey(fromV6SecretKey data: Data, passphrase: String? = nil) throws -> Cv25519DecryptionKey {
        let packets = try parsePackets(data: Array(data))
        guard let secret = packets.first(where: { $0.tag == 7 && v6AlgorithmByte($0.body) == 25 }),
              let pub = v6PublicPortion(body: secret.body) else {
            throw PacketParserError.invalidPacket("No v6 X25519 encryption subkey found")
        }
        let scalar = try v6SecretMaterial(body: secret.body, publicEnd: pub.end, packetTag: secret.tag, passphrase: passphrase)
        guard scalar.count == 32 else {
            throw PacketParserError.invalidPacket("v6 X25519 scalar must be 32 bytes, got \(scalar.count)")
        }
        // v6 X25519 stores the native little-endian scalar; used directly (no reversal).
        let fingerprint = computeV6Fingerprint(packetBody: pub.publicBody)
        return Cv25519DecryptionKey(
            subkeyID: Array(fingerprint.prefix(8)),
            subkeyFingerprint: fingerprint,
            privateKey: scalar,
            kdfHashID: 0,   // v6 X25519 uses a fixed HKDF-SHA256 KDF; these params are unused
            kdfCipherID: 0
        )
    }

    /// v6 X25519 recipient from a transferable public key (tag 14, algo 25).
    static func x25519Recipient(fromV6PublicKey data: Data) throws -> Cv25519Recipient {
        let packets = try parsePackets(data: Array(data))
        guard let pub = packets.first(where: { $0.tag == 14 && v6AlgorithmByte($0.body) == 25 }),
              let parsed = v6PublicPortion(body: pub.body) else {
            throw PacketParserError.invalidPacket("No v6 X25519 encryption subkey found")
        }
        let fingerprint = computeV6Fingerprint(packetBody: parsed.publicBody)
        return Cv25519Recipient(
            subkeyPublicKey: parsed.keyMaterial,
            subkeyFingerprint: fingerprint,
            subkeyID: Array(fingerprint.prefix(8)),
            kdfHashID: 0,
            kdfCipherID: 0
        )
    }

    /// v6 Ed25519 signing-subkey public key (tag 14, algo 27), 32 raw bytes.
    /// Use this to verify an inline signature made by a v6 key, since the signature's
    /// issuer is the signing subkey, not the (certify-only) primary.
    static func ed25519SigningSubkeyPublicKey(fromV6PublicKey data: Data) throws -> [UInt8] {
        let packets = try parsePackets(data: Array(data))
        guard let pub = packets.first(where: { $0.tag == 14 && v6AlgorithmByte($0.body) == 27 }),
              let parsed = v6PublicPortion(body: pub.body) else {
            throw PacketParserError.invalidPacket("No v6 Ed25519 signing subkey found")
        }
        return parsed.keyMaterial
    }

    /// v6 Ed25519 primary public key (tag 6, algo 27), 32 raw bytes. Identities
    /// made by generateV6Identity sign with the primary, so this is the key
    /// their signatures verify under.
    static func ed25519PrimaryPublicKey(fromV6PublicKey data: Data) throws -> [UInt8] {
        let packets = try parsePackets(data: Array(data))
        guard let pub = packets.first(where: { $0.tag == 6 && v6AlgorithmByte($0.body) == 27 }),
              let parsed = v6PublicPortion(body: pub.body), parsed.keyMaterial.count == 32 else {
            throw PacketParserError.invalidPacket("No v6 Ed25519 primary key found")
        }
        return parsed.keyMaterial
    }

    // MARK: - ML-KEM-768 + X25519 subkey (algorithm 35)

    /// The ML-KEM-768 + X25519 encryption subkey of a v6 transferable public
    /// key (tag 14, algo 35), or nil when the key has none.
    static func compositeRecipient(fromV6PublicKey data: Data) throws -> CompositeKEMRecipient? {
        let packets = try parsePackets(data: Array(data))
        guard let pub = packets.first(where: { $0.tag == 14 && v6AlgorithmByte($0.body) == CompositeKEM.algorithmID }) else {
            return nil
        }
        guard let parsed = v6PublicPortion(body: pub.body),
              parsed.keyMaterial.count == CompositeKEM.compositePublicBytes,
              parsed.end == pub.body.count else {
            throw PacketParserError.invalidPacket("Malformed ML-KEM-768 + X25519 subkey")
        }
        return CompositeKEMRecipient(
            subkeyPublicKey: parsed.keyMaterial,
            subkeyFingerprint: computeV6Fingerprint(packetBody: parsed.publicBody)
        )
    }

    /// The ML-KEM-768 + X25519 secret subkey of a v6 transferable secret key
    /// (tag 7, algo 35), or nil when the key has none. Protected material is
    /// unlocked with `passphrase` (see `v6SecretMaterial`); without one it throws.
    static func compositeDecryptionKey(fromV6SecretKey data: Data, passphrase: String? = nil) throws -> CompositeKEMDecryptionKey? {
        let packets = try parsePackets(data: Array(data))
        guard let secret = packets.first(where: { $0.tag == 7 && v6AlgorithmByte($0.body) == CompositeKEM.algorithmID }) else {
            return nil
        }
        guard let parsed = v6PublicPortion(body: secret.body),
              parsed.keyMaterial.count == CompositeKEM.compositePublicBytes,
              parsed.end < secret.body.count else {
            throw PacketParserError.invalidPacket("Malformed ML-KEM-768 + X25519 secret subkey")
        }
        let material: [UInt8]
        if secret.body[parsed.end] == 0 {
            material = Array(secret.body[(parsed.end + 1)...])
        } else {
            material = try v6SecretMaterial(
                body: secret.body, publicEnd: parsed.end, packetTag: secret.tag,
                passphrase: passphrase, length: CompositeKEM.compositeSecretBytes)
        }
        guard material.count == CompositeKEM.compositeSecretBytes else {
            throw PacketParserError.invalidPacket("ML-KEM-768 + X25519 secret material has the wrong length")
        }
        // The stored secret has to belong to the public half beside it.
        guard let rebuilt = try? CompositeKEM.publicKey(fromSecret: Data(material)),
              [UInt8](rebuilt) == parsed.keyMaterial else {
            throw PacketParserError.invalidPacket("ML-KEM-768 + X25519 secret does not match its public key")
        }
        return CompositeKEMDecryptionKey(
            subkeyFingerprint: computeV6Fingerprint(packetBody: parsed.publicBody),
            secretKey: material
        )
    }

    /// True when a v6 transferable secret key needs a passphrase before it can
    /// sign or decrypt: its signing key (a signing subkey when it has one, else
    /// the primary) or its ML-KEM-768 + X25519 subkey is protected. An export
    /// can protect its keys one by one, so both are looked at.
    static func v6SecretKeyNeedsPassphrase(_ data: Data) -> Bool {
        guard let packets = try? parsePackets(data: Array(data)) else { return false }
        func isLocked(_ packet: ParsedPacket?) -> Bool {
            guard let packet, let pub = v6PublicPortion(body: packet.body), pub.end < packet.body.count else { return false }
            return packet.body[pub.end] != 0
        }
        let signing = packets.first(where: { $0.tag == 7 && v6AlgorithmByte($0.body) == 27 })
                   ?? packets.first(where: { $0.tag == 5 && v6AlgorithmByte($0.body) == 27 })
        let composite = packets.first(where: { $0.tag == 7 && v6AlgorithmByte($0.body) == CompositeKEM.algorithmID })
        return isLocked(signing) || isLocked(composite)
    }

    // MARK: - v6 body helpers

    /// Algorithm byte of a v6 key packet body (offset 5), or 0xFF if the body is not v6.
    private static func v6AlgorithmByte(_ body: [UInt8]) -> UInt8 {
        guard body.count > 5, body[0] == 6 else { return 0xFF }
        return body[5]
    }

    /// Parse the public portion of a v6 key packet body:
    ///   version(1)=6 | ctime(4) | algo(1) | matLen(4 BE) | material(matLen)
    /// Returns the algorithm, the exact public-body bytes (for fingerprinting), the
    /// raw key material, and the offset immediately after the public portion.
    private static func v6PublicPortion(body: [UInt8]) -> (algorithm: UInt8, publicBody: [UInt8], keyMaterial: [UInt8], end: Int)? {
        var off = 0
        guard body.count > 10, body[off] == 6 else { return nil }
        off += 1              // version
        off += 4              // creation time
        let algorithm = body[off]; off += 1
        let matLen = Int(body[off]) << 24 | Int(body[off + 1]) << 16 | Int(body[off + 2]) << 8 | Int(body[off + 3])
        off += 4
        guard matLen > 0, off + matLen <= body.count else { return nil }
        let material = Array(body[off..<(off + matLen)])
        off += matLen
        let publicBody = Array(body[0..<off])
        return (algorithm, publicBody, material, off)
    }

    /// Extract raw secret material from a v6 secret key body. Handles unprotected
    /// (S2K usage octet 0), Argon2id + AEAD protected (S2K usage 253) and CFB
    /// protected (S2K usage 254) keys, per RFC 9580 §5.5.3. `length` is the size
    /// of the secret material: 32 for Ed25519 and X25519, 96 for ML-KEM-768 +
    /// X25519. One export can mix the two protections (PGPony Android keeps its
    /// classic keys under 254 and its ML-KEM subkey under 253).
    private static func v6SecretMaterial(body: [UInt8], publicEnd: Int, packetTag: UInt8, passphrase: String?, length: Int = 32) throws -> [UInt8] {
        var off = publicEnd
        guard off < body.count else {
            throw PacketParserError.invalidPacket("v6 secret key: missing S2K usage octet")
        }
        let s2kUsage = body[off]; off += 1

        if s2kUsage == 0 {
            // Unprotected: raw private material, no checksum.
            guard off + length <= body.count else {
                throw PacketParserError.invalidPacket("v6 secret key: private material truncated")
            }
            return Array(body[off..<(off + length)])
        }

        if s2kUsage == 254 {
            // S2K usage 254 (CFB). Wire layout after the usage octet:
            //   len1(1) | cipher(1) | len2(1) | S2K specifier(len2) | IV(16) |
            //   CFB(material | SHA-1(material))
            guard let pass = passphrase, !pass.isEmpty else {
                throw PacketParserError.invalidPacket("v6 protected secret key requires a passphrase")
            }
            guard off + 3 <= body.count else { throw PacketParserError.invalidPacket("v6 secret: truncated (algos)") }
            off += 1  // len1
            let cipherAlgo = body[off]; off += 1
            let specLen = Int(body[off]); off += 1
            guard specLen >= 2, off + specLen <= body.count else {
                throw PacketParserError.invalidPacket("v6 secret: truncated (S2K specifier)")
            }
            let spec = Array(body[off..<(off + specLen)]); off += specLen
            let s2kType = spec[0]
            let hashAlgo = spec[1]
            var salt: [UInt8] = []
            var codedCount: UInt8 = 0
            switch (s2kType, spec.count) {
            case (0, 2):
                break
            case (1, 10):
                salt = Array(spec[2..<10])
            case (3, 11):
                salt = Array(spec[2..<10])
                codedCount = spec[10]
            default:
                throw PacketParserError.invalidPacket("v6 secret: unsupported S2K specifier (type \(s2kType))")
            }
            // S2K.deriveKey knows SHA-1 and SHA-256 only.
            guard hashAlgo == 2 || hashAlgo == 8 else {
                throw PacketParserError.invalidPacket("v6 secret: unsupported S2K hash \(hashAlgo)")
            }
            let keySize = try s2kCipherKeySize(cipherAlgo)
            let key = S2K.deriveKey(
                passphrase: pass, salt: salt, s2kType: s2kType, hashAlgo: hashAlgo,
                codedCount: codedCount, keySize: keySize)
            guard off + 16 <= body.count else { throw PacketParserError.invalidPacket("v6 secret: truncated (IV)") }
            let iv = Array(body[off..<(off + 16)]); off += 16
            let decrypted = aesCFBDecrypt(ciphertext: Array(body[off...]), key: key, iv: iv)
            guard decrypted.count == length + 20 else {
                throw PacketParserError.invalidPacket("v6 secret: private material has the wrong length")
            }
            let material = Array(decrypted[0..<length])
            guard Array(Insecure.SHA1.hash(data: Data(material))) == Array(decrypted[length...]) else {
                throw PacketParserError.invalidPacket("Invalid passphrase")
            }
            return material
        }

        guard s2kUsage == 253 else {
            throw PacketParserError.invalidPacket("v6 secret key: unsupported S2K usage \(s2kUsage)")
        }

        // S2K usage 253 (AEAD). Wire layout after the usage octet:
        //   len1(1) | cipher(1) | aead(1) | len2(1) | S2K specifier(len2) | nonce | ct+tag
        // len1 is a cumulative length; the fields are parsed explicitly below.
        guard let pass = passphrase, !pass.isEmpty else {
            throw PacketParserError.invalidPacket("v6 protected secret key requires a passphrase")
        }
        guard off < body.count else { throw PacketParserError.invalidPacket("v6 secret: truncated (len1)") }
        off += 1  // len1
        guard off + 3 <= body.count else { throw PacketParserError.invalidPacket("v6 secret: truncated (algos)") }
        let cipherAlgo = body[off]; off += 1
        let aeadAlgo   = body[off]; off += 1
        let specLen    = Int(body[off]); off += 1
        guard off + specLen <= body.count else { throw PacketParserError.invalidPacket("v6 secret: truncated (S2K specifier)") }
        let spec = Array(body[off..<(off + specLen)]); off += specLen
        // Argon2 specifier: 0x04 | salt(16) | t(1) | p(1) | m(1); memory = 2^m KiB.
        guard spec.count == 20, spec[0] == 0x04 else {
            throw PacketParserError.invalidPacket("v6 secret: expected Argon2 S2K specifier")
        }
        let salt = Array(spec[1..<17])
        let t = Int(spec[17]); let p = Int(spec[18]); let m = Int(spec[19])
        // 2^18 KiB is 256 MiB. More than that does not fit on a phone, and a
        // crafted key file must not be able to ask for it.
        guard m <= 18 else {
            throw PacketParserError.invalidPacket("v6 secret: Argon2 memory 2^\(m) KiB is more than this device allows")
        }

        let nonceLen = AEADService.nonceSize(for: aeadAlgo)
        guard off + nonceLen <= body.count else { throw PacketParserError.invalidPacket("v6 secret: truncated (nonce)") }
        let nonce = Array(body[off..<(off + nonceLen)]); off += nonceLen
        let ciphertextWithTag = Array(body[off...])

        // KEK = HKDF-SHA256(IKM = Argon2id output, salt = [], info = [tagID, 0x06, cipher, aead]).
        // AAD = tagID || public-key packet body. tagID is the new-format tag octet (0xC0 | tag).
        let tagID = UInt8(0xC0) | packetTag
        let argon2Key = try Argon2Service.deriveKey(
            passphrase: pass, salt: salt, iterations: t, parallelism: p, memoryExponent: m, hashLength: 32)
        let kek = try hkdfSHA256(ikm: argon2Key, salt: [], info: [tagID, 0x06, cipherAlgo, aeadAlgo], outputLength: 32)
        let aad = [tagID] + Array(body[0..<publicEnd])
        let material = try AEADService.decryptWithAppendedTag(
            data: ciphertextWithTag, key: kek, nonce: nonce, aeadAlgo: aeadAlgo, associatedData: aad)
        guard material.count == length else {
            throw PacketParserError.invalidPacket("v6 secret: private material has the wrong length")
        }
        return material
    }
}
