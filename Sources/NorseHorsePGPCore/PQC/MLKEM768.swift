// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

// MLKEM768.swift
// NorseHorsePGPCore
//
// ML-KEM-768 (FIPS 203) through the vendored liboqs build. Raw key
// encapsulation only: the RFC 9980 combiner and the OpenPGP framing sit on
// top of this in CompositeKEM. Ported from PGPonyCore's MLKEMService, cut
// down to the one parameter set this package uses.
//
// The sizes are fixed by FIPS 203 and are checked against liboqs on every
// call, so a mismatched library fails loudly instead of handing the packet
// layer wrong-sized buffers.

import Foundation
import COQS

enum MLKEM768 {

    static let publicKeyBytes = 1184
    static let secretKeyBytes = 2400
    static let ciphertextBytes = 1088
    static let sharedSecretBytes = 32
    /// Keypair seed, d (32) then z (32), as FIPS 203 orders them.
    static let seedBytes = 64

    enum Failure: Error {
        case unavailable
        case badInputSize
        case operationFailed
    }

    /// Wipes a scratch buffer that held secret material. Best effort: Swift
    /// may have made copies of its own.
    static func cleanse(_ bytes: inout [UInt8]) {
        bytes.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { OQS_MEM_cleanse(base, raw.count) }
        }
    }

    private static func withKEM<T>(_ body: (UnsafeMutablePointer<OQS_KEM>) throws -> T) throws -> T {
        guard OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_768) == 1,
              let kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768) else {
            throw Failure.unavailable
        }
        defer { OQS_KEM_free(kem) }
        let k = kem.pointee
        guard k.length_public_key == publicKeyBytes,
              k.length_secret_key == secretKeyBytes,
              k.length_ciphertext == ciphertextBytes,
              k.length_shared_secret == sharedSecretBytes,
              k.length_keypair_seed == seedBytes else {
            throw Failure.unavailable
        }
        return try body(kem)
    }

    /// Expands a 64-octet seed into (publicKey 1184, secretKey 2400). The seed
    /// is what gets stored in a secret key packet; the expanded secret key
    /// only ever lives in memory.
    static func keyPair(seed: [UInt8]) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        guard seed.count == seedBytes else { throw Failure.badInputSize }
        return try withKEM { kem in
            var pk = [UInt8](repeating: 0, count: publicKeyBytes)
            var sk = [UInt8](repeating: 0, count: secretKeyBytes)
            guard OQS_KEM_keypair_derand(kem, &pk, &sk, seed) == OQS_SUCCESS else {
                cleanse(&sk)
                throw Failure.operationFailed
            }
            return (pk, sk)
        }
    }

    /// Encapsulates to a public key: (ciphertext 1088, sharedSecret 32).
    static func encapsulate(publicKey: [UInt8]) throws -> (ciphertext: [UInt8], sharedSecret: [UInt8]) {
        guard publicKey.count == publicKeyBytes else { throw Failure.badInputSize }
        return try withKEM { kem in
            var ct = [UInt8](repeating: 0, count: ciphertextBytes)
            var ss = [UInt8](repeating: 0, count: sharedSecretBytes)
            guard OQS_KEM_encaps(kem, &ct, &ss, publicKey) == OQS_SUCCESS else {
                cleanse(&ss)
                throw Failure.operationFailed
            }
            return (ct, ss)
        }
    }

    /// Decapsulates with the expanded secret key. A tampered ciphertext does
    /// not throw: ML-KEM's implicit rejection returns an unrelated secret, and
    /// the mismatch shows up when the session key fails to unwrap.
    static func decapsulate(ciphertext: [UInt8], secretKey: [UInt8]) throws -> [UInt8] {
        guard ciphertext.count == ciphertextBytes, secretKey.count == secretKeyBytes else {
            throw Failure.badInputSize
        }
        return try withKEM { kem in
            var ss = [UInt8](repeating: 0, count: sharedSecretBytes)
            guard OQS_KEM_decaps(kem, &ss, ciphertext, secretKey) == OQS_SUCCESS else {
                cleanse(&ss)
                throw Failure.operationFailed
            }
            return ss
        }
    }

    static func sha3_256(_ input: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        OQS_SHA3_sha3_256(&out, input, input.count)
        return out
    }
}
