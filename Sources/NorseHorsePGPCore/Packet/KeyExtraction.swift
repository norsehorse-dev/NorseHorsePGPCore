import Foundation
import CryptoKit
import CommonCrypto

// v4 key extraction: bridges stored OpenPGP key bytes to the core's message
// primitives. Ported from the app's PGPService extractors, decoupled to take
// raw Data (no PGPKeyModel / Keychain), v4-only (Ed25519 signing primary +
// Cv25519 encryption subkey — the CarrierPony identity layout).
//
// Reuses the core's S2K, Argon2Service, AEADService, Cv25519ECDHService, and
// parsePackets. Requires the messaging types to be public (spec Part A).
//
// Passphrase handling: unprotected (S2K usage 0) and CFB-protected (254/255) are
// supported for both key types; the Cv25519 subkey additionally supports the
// gpg 2.4 Argon2+AEAD default (usage 253). An Argon2+AEAD-protected Ed25519
// PRIMARY is not handled (matches the app); CarrierPony identities are expected
// unprotected at the PGP layer (storage provides protection).

public extension OpenPGPPacketParser {

    /// Ed25519 OID: 1.3.6.1.4.1.11591.15.1
    private static let ed25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]

    // MARK: - Public entry points

    /// Extract the Ed25519 signing info from a v4 secret key blob. Prefers the
    /// Ed25519 primary (tag 5); falls back to an Ed25519 secret subkey (tag 7).
    static func ed25519SigningInfo(fromSecretKey data: Data, passphrase: String? = nil) throws -> Ed25519SigningInfo {
        let packets = try parsePackets(data: Array(data))
        let candidates = packets.filter { ($0.tag == 5 || $0.tag == 7) && isEdDSAEd25519Packet(body: $0.body) }
        guard let chosen = candidates.first(where: { $0.tag == 5 }) ?? candidates.first else {
            throw PacketParserError.invalidPacket("No Ed25519 signing key found")
        }
        guard let info = try parseEdDSASecretKeyPacket(body: chosen.body, passphrase: passphrase, canonicalFingerprint: nil) else {
            throw PacketParserError.invalidPacket("Failed to parse Ed25519 secret key")
        }
        return info
    }

    /// Extract the Cv25519 decryption key from a v4 secret key blob (tag-7 ECDH subkey).
    static func cv25519DecryptionKey(fromSecretKey data: Data, passphrase: String? = nil) throws -> Cv25519DecryptionKey {
        let packets = try parsePackets(data: Array(data))
        guard let subkey = packets.first(where: { $0.tag == 7 && isECDHCv25519Packet(body: $0.body) }) else {
            throw PacketParserError.invalidPacket("No Cv25519 decryption subkey found")
        }
        guard let key = try parseECDHSecretSubkeyPacket(body: subkey.body, passphrase: passphrase, canonicalFingerprint: nil) else {
            throw PacketParserError.invalidPacket("Failed to parse Cv25519 secret subkey")
        }
        return key
    }

    /// Build a Cv25519 recipient from a contact's v4 public key blob (tag-14 ECDH subkey).
    static func cv25519Recipient(fromPublicKey data: Data) throws -> Cv25519Recipient {
        let packets = try parsePackets(data: Array(data))
        guard let subkey = packets.first(where: { $0.tag == 14 && isECDHCv25519Packet(body: $0.body) }) else {
            throw PacketParserError.invalidPacket("No Cv25519 encryption subkey found")
        }
        guard let recipient = try parseECDHSubkeyPacket(body: subkey.body) else {
            throw PacketParserError.invalidPacket("Failed to parse Cv25519 public subkey")
        }
        return recipient
    }

    // MARK: - Ported v4 parsers and helpers

    private static func parseEdDSASecretKeyPacket(body: [UInt8], passphrase: String? = nil, canonicalFingerprint: [UInt8]? = nil) throws -> Ed25519SigningInfo? {
        var off = 0
        guard body.count > 6 else { return nil }
        
        let version = body[off]; off += 1
        guard version == 4 else { return nil }
        
        off += 4  // Creation time
        
        let algo = body[off]; off += 1
        guard algo == 22 else { return nil }  // EdDSA only
        
        // OID
        guard off < body.count else { return nil }
        let oidLen = Int(body[off]); off += 1
        guard off + oidLen <= body.count else { return nil }
        let oid = Array(body[off..<(off + oidLen)]); off += oidLen
        guard oid == ed25519OID else { return nil }
        
        // Public key MPI (0x40 + 32 bytes)
        guard off + 2 <= body.count else { return nil }
        let qBits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        let qBytes = (qBits + 7) / 8
        guard off + qBytes <= body.count else { return nil }
        off += qBytes  // Skip public key MPI
        
        // End of public portion — compute fingerprint
        let publicBody = Array(body[0..<off])
        let fingerprint: [UInt8]
        if let canonical = canonicalFingerprint {
            fingerprint = canonical
        } else {
            fingerprint = Cv25519ECDHService.subkeyFingerprint(keyBody: publicBody)
        }
        let keyID = Array(fingerprint.suffix(8))
        
        // S2K usage byte
        guard off < body.count else { return nil }
        let s2kUsage = body[off]; off += 1
        
        let privateKeyBytes: [UInt8]
        
        if s2kUsage == 0 {
            // Unprotected
            guard off + 2 <= body.count else { return nil }
            let dBits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
            let dBytes = (dBits + 7) / 8
            guard off + dBytes <= body.count else { return nil }
            privateKeyBytes = Array(body[off..<(off + dBytes)])
            
        } else if s2kUsage == 254 || s2kUsage == 255 {
            // S2K protected
            guard let passphrase = passphrase, !passphrase.isEmpty else {
                throw PacketParserError.invalidPacket("Passphrase required")
            }
            
            guard off < body.count else { return nil }
            let cipherID = body[off]; off += 1
            
            guard off < body.count else { return nil }
            let s2kType = body[off]; off += 1
            
            guard off < body.count else { return nil }
            let s2kHashAlgo = body[off]; off += 1
            
            var salt: [UInt8] = []
            var codedCount: UInt8 = 0
            
            if s2kType == 1 || s2kType == 3 {
                guard off + 8 <= body.count else { return nil }
                salt = Array(body[off..<(off + 8)]); off += 8
            }
            
            if s2kType == 3 {
                guard off < body.count else { return nil }
                codedCount = body[off]; off += 1
            }
            
            let kekSize = try s2kCipherKeySize(cipherID)
            let derivedKey = S2K.deriveKey(
                passphrase: passphrase,
                salt: salt,
                s2kType: s2kType,
                hashAlgo: s2kHashAlgo,
                codedCount: codedCount,
                keySize: kekSize
            )
            
            guard off + 16 <= body.count else { return nil }
            let iv = Array(body[off..<(off + 16)]); off += 16
            
            let encryptedData = Array(body[off...])
            let decrypted = aesCFBDecrypt(ciphertext: encryptedData, key: derivedKey, iv: iv)
            
            if s2kUsage == 254 {
                guard decrypted.count >= 20 else { throw PacketParserError.invalidPacket("Invalid passphrase") }
                let mpiData = Array(decrypted[0..<(decrypted.count - 20)])
                let storedHash = Array(decrypted[(decrypted.count - 20)...])
                
                var computedHash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
                CC_SHA1(mpiData, CC_LONG(mpiData.count), &computedHash)
                
                guard storedHash == computedHash else { throw PacketParserError.invalidPacket("Invalid passphrase") }
                
                guard mpiData.count >= 2 else { return nil }
                let dBits = Int(mpiData[0]) << 8 | Int(mpiData[1])
                let dBytes = (dBits + 7) / 8
                guard 2 + dBytes <= mpiData.count else { return nil }
                privateKeyBytes = Array(mpiData[2..<(2 + dBytes)])
            } else {
                guard decrypted.count >= 2 else { throw PacketParserError.invalidPacket("Invalid passphrase") }
                let mpiData = Array(decrypted[0..<(decrypted.count - 2)])
                let storedChecksum = UInt16(decrypted[decrypted.count - 2]) << 8 | UInt16(decrypted[decrypted.count - 1])
                let computedChecksum = mpiData.reduce(UInt16(0)) { ($0 &+ UInt16($1)) }
                guard storedChecksum == computedChecksum else { throw PacketParserError.invalidPacket("Invalid passphrase") }
                
                guard mpiData.count >= 2 else { return nil }
                let dBits = Int(mpiData[0]) << 8 | Int(mpiData[1])
                let dBytes = (dBits + 7) / 8
                guard 2 + dBytes <= mpiData.count else { return nil }
                privateKeyBytes = Array(mpiData[2..<(2 + dBytes)])
            }
        } else {
            return nil
        }
        
        guard privateKeyBytes.count == 32 else { return nil }
        
        let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
        
        return Ed25519SigningInfo(
            privateKey: signingKey,
            keyID: keyID,
            fingerprint: fingerprint
        )
    }

    private static func parseECDHSubkeyPacket(body: [UInt8]) throws -> Cv25519Recipient? {
        var off = 0
        guard body.count > 6 else { return nil }
        
        let version = body[off]; off += 1
        guard version == 4 else { return nil }
        
        // Creation time (4 bytes)
        off += 4
        
        // Algorithm
        let algo = body[off]; off += 1
        guard algo == 18 else { return nil }  // ECDH only
        
        // OID
        guard off < body.count else { return nil }
        let oidLen = Int(body[off]); off += 1
        guard off + oidLen <= body.count else { return nil }
        let oid = Array(body[off..<(off + oidLen)]); off += oidLen
        
        // Check it's Cv25519
        guard oid == Cv25519ECDHService.cv25519OID else { return nil }
        
        // Public key MPI
        guard off + 2 <= body.count else { return nil }
        let qBits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        let qBytes = (qBits + 7) / 8
        guard off + qBytes <= body.count else { return nil }
        var pubKey = Array(body[off..<(off + qBytes)]); off += qBytes
        
        // Strip 0x40 prefix
        if pubKey.first == 0x40 {
            pubKey = Array(pubKey.dropFirst())
        }
        guard pubKey.count == 32 else { return nil }
        
        // KDF params
        guard off < body.count else { return nil }
        let kdfLen = Int(body[off]); off += 1
        guard kdfLen >= 3, off + kdfLen <= body.count else { return nil }
        off += 1  // Reserved byte (0x01)
        let kdfHash = body[off]; off += 1
        let kdfCipher = body[off]; off += 1
        
        // Compute subkey fingerprint
        let fingerprint = Cv25519ECDHService.subkeyFingerprint(keyBody: body)
        let keyID = Array(fingerprint.suffix(8))
        
        return Cv25519Recipient(
            subkeyPublicKey: pubKey,
            subkeyFingerprint: fingerprint,
            subkeyID: keyID,
            kdfHashID: kdfHash,
            kdfCipherID: kdfCipher
        )
    }

    private static func parseECDHSecretSubkeyPacket(body: [UInt8], passphrase: String? = nil, canonicalFingerprint: [UInt8]? = nil) throws -> Cv25519DecryptionKey? {
        // Secret subkey has the same prefix as public subkey, plus secret material
        var off = 0
        guard body.count > 6 else { return nil }
        
        let version = body[off]; off += 1
        guard version == 4 else { return nil }
        
        off += 4  // Creation time
        
        let algo = body[off]; off += 1
        guard algo == 18 else { return nil }
        
        // OID
        let oidLen = Int(body[off]); off += 1
        let oid = Array(body[off..<(off + oidLen)]); off += oidLen
        guard oid == Cv25519ECDHService.cv25519OID else { return nil }
        
        // Public key MPI
        let publicPartStart = 0
        let qBits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        let qBytes = (qBits + 7) / 8
        off += qBytes
        
        // KDF params
        let kdfLen = Int(body[off]); off += 1
        guard kdfLen >= 3, off + kdfLen <= body.count else { return nil }
        off += 1  // Reserved (0x01)
        let kdfHash = body[off]; off += 1
        let kdfCipher = body[off]; off += 1
        // Skip any remaining KDF bytes we don't parse
        if kdfLen > 3 {
            off += kdfLen - 3
        }
        
        // Compute fingerprint: prefer canonical (tag-14) fingerprint when available,
        // fall back to computing from the tag-7 body's public portion.
        let fingerprint: [UInt8]
        if let canonical = canonicalFingerprint {
            fingerprint = canonical
            let tag7PublicBody = Array(body[publicPartStart..<off])
            let tag7Fingerprint = Cv25519ECDHService.subkeyFingerprint(keyBody: tag7PublicBody)
            if tag7Fingerprint != canonical {
                pgpDebugLog("DEBUG Cv25519 FP: *** FINGERPRINT MISMATCH ***")
                pgpDebugLog("DEBUG Cv25519 FP: tag-7 body fingerprint = \(tag7Fingerprint.map { String(format: "%02x", $0) }.joined())")
                pgpDebugLog("DEBUG Cv25519 FP: tag-14 canonical fingerprint = \(canonical.map { String(format: "%02x", $0) }.joined())")
                pgpDebugLog("DEBUG Cv25519 FP: Using canonical (tag-14) fingerprint for KDF")
            }
        } else {
            // No public key available — compute from tag-7 body (PGPony-generated keys)
            let publicBody = Array(body[publicPartStart..<off])
            fingerprint = Cv25519ECDHService.subkeyFingerprint(keyBody: publicBody)
            pgpDebugLog("DEBUG Cv25519 FP: no canonical fingerprint available, computed from tag-7 body")
        }
        let keyID = Array(fingerprint.suffix(8))
        
        pgpDebugLog("DEBUG Cv25519 FP: fingerprint = \(fingerprint.map { String(format: "%02x", $0) }.joined())")
        pgpDebugLog("DEBUG Cv25519 FP: keyID = \(keyID.map { String(format: "%02x", $0) }.joined())")
        pgpDebugLog("DEBUG Cv25519 FP: kdfLen=\(kdfLen), kdfHash=\(kdfHash), kdfCipher=\(kdfCipher)")
        
        // S2K usage byte
        guard off < body.count else { return nil }
        let s2kUsage = body[off]; off += 1
        
        let privateKey: [UInt8]
        
        if s2kUsage == 0 {
            // Unprotected — MPI is in the clear
            guard off + 2 <= body.count else { return nil }
            let dBits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
            let dBytes = (dBits + 7) / 8
            guard off + dBytes <= body.count else { return nil }
            privateKey = Array(body[off..<(off + dBytes)].reversed())  // Cv25519 scalar is stored big-endian; reverse for CryptoKit
            
        } else if s2kUsage == 254 || s2kUsage == 255 {
            // S2K protected — need passphrase
            guard let passphrase = passphrase, !passphrase.isEmpty else {
                pgpDebugLog("DEBUG: Cv25519 subkey is S2K-protected but no passphrase provided")
                throw PacketParserError.invalidPacket("Passphrase required")
            }
            
            // Symmetric cipher ID
            guard off < body.count else { return nil }
            let cipherID = body[off]; off += 1
            
            // S2K specifier
            guard off < body.count else { return nil }
            let s2kType = body[off]; off += 1
            
            // S2K hash algorithm
            guard off < body.count else { return nil }
            let s2kHashAlgo = body[off]; off += 1
            
            var salt: [UInt8] = []
            var codedCount: UInt8 = 0
            
            if s2kType == 1 || s2kType == 3 {
                // Salted or Iterated+Salted — read 8-byte salt
                guard off + 8 <= body.count else { return nil }
                salt = Array(body[off..<(off + 8)]); off += 8
            }
            
            if s2kType == 3 {
                // Iterated — read coded count
                guard off < body.count else { return nil }
                codedCount = body[off]; off += 1
            }
            
            // Derive the key encryption key from passphrase
            let kekSize = try s2kCipherKeySize(cipherID)
            let blockSize = 16  // AES always 16-byte blocks
            let derivedKey = S2K.deriveKey(
                passphrase: passphrase,
                salt: salt,
                s2kType: s2kType,
                hashAlgo: s2kHashAlgo,
                codedCount: codedCount,
                keySize: kekSize
            )
            
            // IV follows (one block)
            guard off + blockSize <= body.count else { return nil }
            let iv = Array(body[off..<(off + blockSize)]); off += blockSize
            
            // Encrypted data is the rest
            let encryptedData = Array(body[off...])
            
            // Decrypt with AES-CFB
            let decrypted = aesCFBDecrypt(ciphertext: encryptedData, key: derivedKey, iv: iv)
            
            // Verify checksum
            if s2kUsage == 254 {
                // SHA-1 checksum: last 20 bytes of decrypted are SHA-1 of everything before
                guard decrypted.count >= 20 else {
                    throw PacketParserError.invalidPacket("Invalid passphrase")
                }
                let mpiData = Array(decrypted[0..<(decrypted.count - 20)])
                let storedHash = Array(decrypted[(decrypted.count - 20)...])
                
                var computedHash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
                CC_SHA1(mpiData, CC_LONG(mpiData.count), &computedHash)
                
                guard storedHash == computedHash else {
                    throw PacketParserError.invalidPacket("Invalid passphrase")
                }
                
                // Parse the MPI from decrypted data
                guard mpiData.count >= 2 else { return nil }
                let dBits = Int(mpiData[0]) << 8 | Int(mpiData[1])
                let dBytes = (dBits + 7) / 8
                guard 2 + dBytes <= mpiData.count else { return nil }
                let rawMPI = Array(mpiData[2..<(2 + dBytes)])
                // GnuPG stores Cv25519 private keys as big-endian MPIs,
                // but CryptoKit expects little-endian (RFC 7748).
                // Reverse the bytes for X25519 key agreement.
                privateKey = rawMPI.reversed()
                
            } else {
                // s2kUsage == 255: two-octet checksum
                guard decrypted.count >= 2 else {
                    throw PacketParserError.invalidPacket("Invalid passphrase")
                }
                let mpiData = Array(decrypted[0..<(decrypted.count - 2)])
                let storedChecksum = UInt16(decrypted[decrypted.count - 2]) << 8 | UInt16(decrypted[decrypted.count - 1])
                let computedChecksum = mpiData.reduce(UInt16(0)) { ($0 &+ UInt16($1)) }
                
                guard storedChecksum == computedChecksum else {
                    throw PacketParserError.invalidPacket("Invalid passphrase")
                }
                
                guard mpiData.count >= 2 else { return nil }
                let dBits = Int(mpiData[0]) << 8 | Int(mpiData[1])
                let dBytes = (dBits + 7) / 8
                guard 2 + dBytes <= mpiData.count else { return nil }
                let rawMPI = Array(mpiData[2..<(2 + dBytes)])
                privateKey = rawMPI.reversed()
            }
            
        } else if s2kUsage == 253 {
            // AEAD + Argon2id protected (GnuPG 2.4.x default for v4 keys)
            guard let passphrase = passphrase, !passphrase.isEmpty else {
                pgpDebugLog("DEBUG: Cv25519 subkey is Argon2+AEAD protected but no passphrase provided")
                throw PacketParserError.invalidPacket("Passphrase required")
            }

            // V4 s2kUsage 253 format (different from v6):
            //   cipher(1) | aead(1) | s2k_type(1)=4 | salt(16) | t(1) | p(1) | m(1) | nonce(N) | encrypted(...)

            // Cipher algorithm
            guard off < body.count else { return nil }
            let cipherAlgo = body[off]; off += 1

            // AEAD algorithm
            guard off < body.count else { return nil }
            let aeadAlgo = body[off]; off += 1

            // S2K specifier
            guard off < body.count else { return nil }
            let s2kType = body[off]; off += 1
            guard s2kType == 4 else {
                pgpDebugLog("DEBUG: V4 Argon2: expected S2K type 4, got \(s2kType)")
                return nil
            }

            // Argon2 parameters: salt(16) | t(1) | p(1) | m(1)
            guard off + 19 <= body.count else { return nil }
            let argon2Salt = Array(body[off..<(off + 16)]); off += 16
            let argon2T = Int(body[off]); off += 1
            let argon2P = Int(body[off]); off += 1
            let argon2M = Int(body[off]); off += 1

            pgpDebugLog("DEBUG V4 Argon2: cipher=\(cipherAlgo), aead=\(aeadAlgo), salt=\(argon2Salt.prefix(4).map { String(format: "%02x", $0) }.joined())..., t=\(argon2T), p=\(argon2P), m=\(argon2M)")

            // Derive key via Argon2id
            let keySize = try s2kCipherKeySize(cipherAlgo)
            let derivedKey = try Argon2Service.deriveKey(
                passphrase: passphrase,
                salt: argon2Salt,
                iterations: argon2T,
                parallelism: argon2P,
                memoryExponent: argon2M,
                hashLength: keySize
            )

            // AEAD nonce
            let nonceLen = AEADService.nonceSize(for: aeadAlgo)
            guard nonceLen > 0, off + nonceLen <= body.count else {
                pgpDebugLog("DEBUG V4 Argon2: bad nonce length or truncated, aeadAlgo=\(aeadAlgo)")
                return nil
            }
            let nonce = Array(body[off..<(off + nonceLen)]); off += nonceLen

            // Encrypted data is the rest
            let encryptedData = Array(body[off...])

            pgpDebugLog("DEBUG V4 Argon2: nonceLen=\(nonceLen), encryptedLen=\(encryptedData.count), keySize=\(keySize)")

            // Decrypt with AEAD
            // For v4 keys with s2kUsage 253, GnuPG uses empty associated data.
            // (Only v6 keys use packet framing as AD per RFC 9580.)
            let decrypted = try AEADService.decryptWithAppendedTag(
                data: encryptedData,
                key: derivedKey,
                nonce: nonce,
                aeadAlgo: aeadAlgo,
                associatedData: []
            )

            pgpDebugLog("DEBUG V4 Argon2: decrypted \(decrypted.count) bytes of secret key material")

            // Decrypted data should contain the raw 32-byte Cv25519 private key
            // For v4, it's an MPI: 2-byte bit count + key bytes
            if decrypted.count >= 34 {
                // MPI format
                let dBits = Int(decrypted[0]) << 8 | Int(decrypted[1])
                let dBytes = (dBits + 7) / 8
                guard 2 + dBytes <= decrypted.count, dBytes == 32 else {
                    pgpDebugLog("DEBUG V4 Argon2: unexpected MPI size: bits=\(dBits), bytes=\(dBytes)")
                    return nil
                }
                privateKey = Array(decrypted[2..<(2 + dBytes)].reversed())  // Cv25519 big-endian -> little-endian
            } else if decrypted.count == 32 {
                // Raw format (unlikely for v4 but handle it)
                privateKey = Array(decrypted[0..<32].reversed())  // Cv25519 big-endian -> little-endian
            } else {
                pgpDebugLog("DEBUG V4 Argon2: decrypted key material is \(decrypted.count) bytes, expected 32 or 34")
                return nil
            }

        } else {
            // S2K usage is the cipher algorithm ID directly (legacy format)
            pgpDebugLog("DEBUG: Cv25519 subkey uses legacy S2K format (usage=\(s2kUsage)) — not supported")
            return nil
        }
        
        guard privateKey.count == 32 else {
            pgpDebugLog("DEBUG: Cv25519 private key is \(privateKey.count) bytes, expected 32")
            return nil
        }
        
        return Cv25519DecryptionKey(
            subkeyID: keyID,
            subkeyFingerprint: fingerprint,
            privateKey: privateKey,
            kdfHashID: kdfHash,
            kdfCipherID: kdfCipher
        )
    }

    private static func s2kCipherKeySize(_ cipherID: UInt8) throws -> Int {
        switch cipherID {
        case 7: return 16   // AES-128
        case 8: return 24   // AES-192
        case 9: return 32   // AES-256
        default: throw PacketParserError.invalidPacket("Unsupported S2K cipher: \(cipherID)")
        }
    }

    private static func aesCFBDecrypt(ciphertext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        var plaintext = [UInt8](repeating: 0, count: ciphertext.count)
        var currentIV = iv
        let blockSize = 16
        
        var offset = 0
        while offset < ciphertext.count {
            var encryptedBlock = [UInt8](repeating: 0, count: blockSize)
            var outLen = 0
            
            var cryptorRef: CCCryptorRef?
            CCCryptorCreate(
                CCOperation(kCCEncrypt),  // CFB decrypt uses AES ENCRYPT on the IV
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                key, key.count,
                nil,
                &cryptorRef
            )
            
            if let cryptor = cryptorRef {
                CCCryptorUpdate(
                    cryptor,
                    currentIV, blockSize,
                    &encryptedBlock, blockSize,
                    &outLen
                )
                CCCryptorRelease(cryptor)
            }
            
            let blockEnd = min(offset + blockSize, ciphertext.count)
            for i in offset..<blockEnd {
                plaintext[i] = ciphertext[i] ^ encryptedBlock[i - offset]
            }
            
            // Feedback: next IV = CIPHERTEXT block (not plaintext — this is CFB decrypt)
            let blockLen = blockEnd - offset
            if blockLen == blockSize {
                currentIV = Array(ciphertext[offset..<blockEnd])
            } else {
                currentIV = Array(ciphertext[offset..<blockEnd]) + Array(currentIV[blockLen...])
            }
            
            offset += blockSize
        }
        
        return plaintext
    }

    private static func isEdDSAEd25519Packet(body: [UInt8]) -> Bool {
        guard body.count > 7 else { return false }
        let version = body[0]

        if version == 6 {
            // V6: algorithm byte is at offset 5, algo 27 = Ed25519 (native, no OID)
            return body[5] == 27
        } else if version == 4 {
            // V4: algo 22 = EdDSA, then check for Ed25519 OID
            guard body[5] == 22 else { return false }
            let oidLen = Int(body[6])
            guard 7 + oidLen <= body.count else { return false }
            let oid = Array(body[7..<(7 + oidLen)])
            return oid == ed25519OID
        }
        return false
    }

    private static func isECDHCv25519Packet(body: [UInt8]) -> Bool {
        guard body.count > 7 else { return false }
        let version = body[0]

        if version == 6 {
            // V6: algorithm byte is at offset 5, algo 25 = X25519 (native, no OID)
            return body[5] == 25
        } else if version == 4 {
            // V4: algo 18 = ECDH, then check for Cv25519 OID
            guard body[5] == 18 else { return false }
            let oidLen = Int(body[6])
            guard 7 + oidLen <= body.count else { return false }
            let oid = Array(body[7..<(7 + oidLen)])
            return oid == Cv25519ECDHService.cv25519OID
        }
        return false
    }
}
