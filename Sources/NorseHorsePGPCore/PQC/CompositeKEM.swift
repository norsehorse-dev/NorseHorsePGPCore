// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// CompositeKEM.swift
// NorseHorsePGPCore
//
// The RFC 9980 composite KEM, algorithm 35: ML-KEM-768 with X25519. A sender
// encapsulates to both halves of the recipient's key and feeds both shares
// through the RFC 9980 combiner to get a 32-octet key-encryption key, which
// wraps the session key with AES-256 Key Wrap (RFC 3394).
//
// Wire layouts, identical to the Android core (CPCompositeKem.kt):
//   composite public = X25519 public (32) then ML-KEM-768 public (1184)
//   composite secret = X25519 secret (32) then ML-KEM-768 seed (64)
//
// Ported from PGPonyCore's CompositeKEMService, cut down to this one suite.
// The combiner's byte layout is pinned by a known-answer test and by a vector
// from a third implementation that the Android core replays too. Do not
// change a constant here without running both.

import Foundation
import CryptoKit
import Security

public enum CompositeKEMError: Error {
    /// A key, ciphertext or session key had the wrong length.
    case badLength
    /// The X25519 half failed: an invalid key, or a low-order ephemeral.
    case keyAgreementFailed
    /// The ML-KEM half failed inside liboqs, or this build lacks ML-KEM-768.
    case mlkemFailed
    /// The session key did not unwrap: wrong key or altered data.
    case unwrapFailed
    case randomFailed
}

public enum CompositeKEM {

    /// OpenPGP public-key algorithm ID for ML-KEM-768 + X25519.
    public static let algorithmID: UInt8 = 35

    public static let x25519Bytes = 32
    public static let mlkemPublicBytes = MLKEM768.publicKeyBytes
    public static let mlkemSeedBytes = MLKEM768.seedBytes
    public static let mlkemCiphertextBytes = MLKEM768.ciphertextBytes
    public static let compositePublicBytes = x25519Bytes + mlkemPublicBytes
    public static let compositeSecretBytes = x25519Bytes + mlkemSeedBytes
    public static let kekBytes = 32

    static let domainSeparator: [UInt8] = Array("OpenPGPCompositeKDFv1".utf8)

    public struct KeyPair {
        public let publicKey: Data
        public let secretKey: Data
    }

    public struct Encapsulation {
        /// The sender's one-time X25519 public key (32).
        public let ephemeralPublic: Data
        public let mlkemCiphertext: Data
        public let kek: Data
    }

    // MARK: - Keys

    public static func generateKeyPair() throws -> KeyPair {
        var seed = [UInt8](repeating: 0, count: mlkemSeedBytes)
        guard SecRandomCopyBytes(kSecRandomDefault, seed.count, &seed) == errSecSuccess else {
            throw CompositeKEMError.randomFailed
        }
        defer { MLKEM768.cleanse(&seed) }
        let x = Curve25519.KeyAgreement.PrivateKey()
        let expandedPublic = try expandPublic(seed: seed)
        return KeyPair(publicKey: x.publicKey.rawRepresentation + Data(expandedPublic),
                       secretKey: x.rawRepresentation + Data(seed))
    }

    /// Rebuilds the composite public key from a composite secret key.
    public static func publicKey(fromSecret compositeSecret: Data) throws -> Data {
        let (xSecret, seed) = try splitSecret(compositeSecret)
        let x: Curve25519.KeyAgreement.PrivateKey
        do { x = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(xSecret)) }
        catch { throw CompositeKEMError.keyAgreementFailed }
        return x.publicKey.rawRepresentation + Data(try expandPublic(seed: seed))
    }

    // MARK: - Encapsulation

    public static func encapsulate(compositePublic: Data) throws -> Encapsulation {
        let (xPublic, mlkemPublic) = try splitPublic(compositePublic)
        var mlkem: (ciphertext: [UInt8], sharedSecret: [UInt8])
        do { mlkem = try MLKEM768.encapsulate(publicKey: mlkemPublic) }
        catch { throw CompositeKEMError.mlkemFailed }
        defer { MLKEM768.cleanse(&mlkem.sharedSecret) }

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = [UInt8](ephemeral.publicKey.rawRepresentation)
        var ecdh = try agree(secret: ephemeral, peerPublic: xPublic)
        defer { MLKEM768.cleanse(&ecdh) }

        let kek = combine(mlkemShare: mlkem.sharedSecret, ecdhShare: ecdh,
                          ephemeralPublic: ephemeralPublic, recipientX25519Public: xPublic)
        return Encapsulation(ephemeralPublic: Data(ephemeralPublic),
                             mlkemCiphertext: Data(mlkem.ciphertext),
                             kek: Data(kek))
    }

    /// Recomputes the key-encryption key from what a sender put in the PKESK.
    /// A wrong key or an altered ML-KEM ciphertext does not throw here: it
    /// yields a different key, and unwrapSessionKey then fails.
    public static func decapsulate(ephemeralPublic: Data,
                                   mlkemCiphertext: Data,
                                   compositeSecret: Data) throws -> Data {
        guard ephemeralPublic.count == x25519Bytes,
              mlkemCiphertext.count == mlkemCiphertextBytes else {
            throw CompositeKEMError.badLength
        }
        let (xSecretBytes, seed) = try splitSecret(compositeSecret)
        let xSecret: Curve25519.KeyAgreement.PrivateKey
        do { xSecret = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(xSecretBytes)) }
        catch { throw CompositeKEMError.keyAgreementFailed }
        let xPublic = [UInt8](xSecret.publicKey.rawRepresentation)

        var expanded: (publicKey: [UInt8], secretKey: [UInt8])
        var mlkemShare: [UInt8]
        do {
            expanded = try MLKEM768.keyPair(seed: seed)
            defer { MLKEM768.cleanse(&expanded.secretKey) }
            mlkemShare = try MLKEM768.decapsulate(ciphertext: [UInt8](mlkemCiphertext),
                                                  secretKey: expanded.secretKey)
        } catch { throw CompositeKEMError.mlkemFailed }
        defer { MLKEM768.cleanse(&mlkemShare) }

        let ephemeral = [UInt8](ephemeralPublic)
        var ecdh = try agree(secret: xSecret, peerPublic: ephemeral)
        defer { MLKEM768.cleanse(&ecdh) }

        return Data(combine(mlkemShare: mlkemShare, ecdhShare: ecdh,
                            ephemeralPublic: ephemeral, recipientX25519Public: xPublic))
    }

    // MARK: - Session key wrap (RFC 3394, AES-256)

    public static func wrapSessionKey(kek: Data, sessionKey: Data) throws -> Data {
        guard kek.count == kekBytes, sessionKey.count >= 16, sessionKey.count % 8 == 0 else {
            throw CompositeKEMError.badLength
        }
        do { return Data(try AESKeyWrap.wrap(plaintext: [UInt8](sessionKey), kek: [UInt8](kek))) }
        catch { throw CompositeKEMError.badLength }
    }

    public static func unwrapSessionKey(kek: Data, wrapped: Data) throws -> Data {
        guard kek.count == kekBytes, wrapped.count >= 24, wrapped.count % 8 == 0 else {
            throw CompositeKEMError.badLength
        }
        do { return Data(try AESKeyWrap.unwrap(ciphertext: [UInt8](wrapped), kek: [UInt8](kek))) }
        catch { throw CompositeKEMError.unwrapFailed }
    }

    // MARK: - Combiner (RFC 9980)

    /// KEK = SHA3-256(mlkemShare, ecdhShare, ephemeralPublic,
    /// recipientX25519Public, algorithm ID, domain separator, its length).
    public static func combine(mlkemShare: [UInt8],
                               ecdhShare: [UInt8],
                               ephemeralPublic: [UInt8],
                               recipientX25519Public: [UInt8]) -> [UInt8] {
        var input = [UInt8]()
        input.reserveCapacity(32 * 4 + 2 + domainSeparator.count)
        input.append(contentsOf: mlkemShare)
        input.append(contentsOf: ecdhShare)
        input.append(contentsOf: ephemeralPublic)
        input.append(contentsOf: recipientX25519Public)
        input.append(algorithmID)
        input.append(contentsOf: domainSeparator)
        input.append(UInt8(domainSeparator.count))
        defer { MLKEM768.cleanse(&input) }
        return MLKEM768.sha3_256(input)
    }

    // MARK: - Internals

    static func splitPublic(_ compositePublic: Data) throws -> (x25519: [UInt8], mlkem: [UInt8]) {
        guard compositePublic.count == compositePublicBytes else { throw CompositeKEMError.badLength }
        let bytes = [UInt8](compositePublic)
        return (Array(bytes[0..<x25519Bytes]), Array(bytes[x25519Bytes...]))
    }

    static func splitSecret(_ compositeSecret: Data) throws -> (x25519: [UInt8], seed: [UInt8]) {
        guard compositeSecret.count == compositeSecretBytes else { throw CompositeKEMError.badLength }
        let bytes = [UInt8](compositeSecret)
        return (Array(bytes[0..<x25519Bytes]), Array(bytes[x25519Bytes...]))
    }

    private static func expandPublic(seed: [UInt8]) throws -> [UInt8] {
        do {
            var pair = try MLKEM768.keyPair(seed: seed)
            MLKEM768.cleanse(&pair.secretKey)
            return pair.publicKey
        } catch { throw CompositeKEMError.mlkemFailed }
    }

    /// Raw X25519. An all-zero result means the peer sent a low-order point,
    /// which would make the share predictable, so it is refused outright
    /// whether or not CryptoKit already threw.
    private static func agree(secret: Curve25519.KeyAgreement.PrivateKey,
                              peerPublic: [UInt8]) throws -> [UInt8] {
        do {
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(peerPublic))
            let shared = try secret.sharedSecretFromKeyAgreement(with: peer)
            let bytes = shared.withUnsafeBytes { [UInt8]($0) }
            guard bytes.contains(where: { $0 != 0 }) else { throw CompositeKEMError.keyAgreementFailed }
            return bytes
        } catch { throw CompositeKEMError.keyAgreementFailed }
    }
}
