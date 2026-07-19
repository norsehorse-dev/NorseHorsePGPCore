// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import XCTest
@testable import NorseHorsePGPCore

/// End-to-end v6 (RFC 9580) conformance for the messaging path. Two identities,
/// each a certify-only Ed25519 primary + Ed25519 signing subkey + X25519
/// encryption subkey, unprotected (S2K usage 0), are built as genuine RFC 9580
/// key streams by an independent encoder and base64-embedded. These prove the v6
/// extractors parse native-format v6 key material and that build -> open
/// round-trips with a signing-subkey-derived sender. Hermetic: no external tools.
final class V6ConformanceTests: XCTestCase {

    // v6 fingerprints are SHA-256 (64 hex); the signer is the Ed25519 SIGNING SUBKEY.
    static let aliceSignSubkeyFpr = "FCAD4059B644035F98E7FD7386ED05F22D7B0E229965F417F1F7697D6011C817"

    static let aliceSecB64 = "xUsGZ3SuIBsAAAAgzM6zmkTVUuZaIuHPheCue9GNSP574ZH2ZztAdZDp5XUA4PCtJftYi0slahoM96JiNtxL2mPzlzFkyRNPdIkbVmHHSwZndK4hGwAAACDP+hoZjeFTg4lKiy4i1pEwqiaUiQXhGJdwvfCX6UMQcQAe1S8EMM/RV6M7Jb27z2RoQQLyrKW+mq3HIiT+NPXPMcdLBmd0riIZAAAAIOL4w0VzDjCdnN/2ku4ZLf96H9CqyuoRjtSz8ShzgxxAAIAQq21e7LGtbTYDc+456FUH8SSyzJdvEtQekIsusQNg"
    static let alicePubB64 = "xioGZ3SuIBsAAAAgzM6zmkTVUuZaIuHPheCue9GNSP574ZH2ZztAdZDp5XXOKgZndK4hGwAAACDP+hoZjeFTg4lKiy4i1pEwqiaUiQXhGJdwvfCX6UMQcc4qBmd0riIZAAAAIOL4w0VzDjCdnN/2ku4ZLf96H9CqyuoRjtSz8ShzgxxA"
    static let bobSecB64 = "xUsGZ3SuhBsAAAAgoA605kL6E8TwIYR0i/pBDAPe3BaWpQt/AUPbmH0ESJMAuv9t6sInOWvPAP1XaspNwKym4oROeeZqwHeq41ghNZ/HSwZndK6FGwAAACDRavXd4eRHZsEvRIIX6kxAV5KxUgX9Cl9BuEChv3C5NwD3bCABZmJIpZGFbexsh8n6iOg9MliYviy40LozmYlWQcdLBmd0roYZAAAAIGh68+Ea/jqrDo9rkqp8w2Twk0OwshNnVpHBwjo/HztFABAwc2+Uyl7Lvc3rfLWJxx6ol9VeaFJGVgZfdRdkAldT"
    static let bobPubB64 = "xioGZ3SuhBsAAAAgoA605kL6E8TwIYR0i/pBDAPe3BaWpQt/AUPbmH0ESJPOKgZndK6FGwAAACDRavXd4eRHZsEvRIIX6kxAV5KxUgX9Cl9BuEChv3C5N84qBmd0roYZAAAAIGh68+Ea/jqrDo9rkqp8w2Twk0OwshNnVpHBwjo/HztF"

    // Argon2id + AES-256-OCB protected (S2K usage 253) secret keys for the SAME
    // identities (public keys/fingerprints unchanged, so the public fixtures and
    // expected fingerprints are reused).
    static let v6Passphrase = "hunter2-carrierpony-v6"
    static let aliceSecProtB64 = "xYIGZ3SuIBsAAAAgzM6zmkTVUuZaIuHPheCue9GNSP574ZH2ZztAdZDp5XX9JgkCFATaq1GVmZoHOWDjzlIgDBUdAwQOfiS6xHr8LS6NoKqJS81bGOv25ZmAD2Voq2wSu+/qreUPJBlpRWmJnuYjZGQi0wGbqgOFr45omS4xL7LrpW5Bx4IGZ3SuIRsAAAAgz/oaGY3hU4OJSosuItaRMKomlIkF4RiXcL3wl+lDEHH9JgkCFAQEBmsAuS4ZEUqcFv/kWLvGAwQORVqMXcH4VgfTC+N+TSBrTTxQ4aggZqDgRG4s+jxWXA7ItXCXpp05U5QH4GAfraUiBDQ78Cg6KdYIw4n4zbYOx4IGZ3SuIhkAAAAg4vjDRXMOMJ2c3/aS7hkt/3of0KrK6hGO1LPxKHODHED9JgkCFARqO7BUeQzSyWygYmOievtCAwQOQZWurt/nt2Jmc1i5KBm7YZZA4PNRNtoWvyozrwk+6W+RTzvr9ioYlXBuzGa7mIADvLq6da/XGqNzbA/aHQpK"
    static let bobSecProtB64 = "xYIGZ3SuhBsAAAAgoA605kL6E8TwIYR0i/pBDAPe3BaWpQt/AUPbmH0ESJP9JgkCFAR41ibtxj07bE/vP8x3/QvaAwQO16CDmxlFGM+tXsE2feIhjW9AILZXauuQd8+HViL1mPQv4DYqu03gkXpxHaaWUfW8kbwe9pP14HLDTQoT6m3wx4IGZ3SuhRsAAAAg0Wr13eHkR2bBL0SCF+pMQFeSsVIF/QpfQbhAob9wuTf9JgkCFATJp2BOHsdm1uBqkkRXXQ6nAwQOFau7bp5OmVEL06c4CV/yD7sP57s5K9MxtyesCB1Nx7tuZ6Te0sGgWSr+bb13SK6Bqyo/OiCWzE0RU2SR4h4Wx4IGZ3SuhhkAAAAgaHrz4Rr+OqsOj2uSqnzDZPCTQ7CyE2dWkcHCOj8fO0X9JgkCFAQk4Rn7cEVhO/VkHz8RVbpLAwQOCZ0+jmMUfTKzUJpJEKCsXuEvc/1RjM0JUK0MIdYh1+cIQRFW3f61oLPIzruSPCp1YZHkfeE1To/34/n6/6p+"

    private func d(_ b64: String) -> Data { Data(base64Encoded: b64)! }
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02X", $0) }.joined() }

    // Extractors parse native v6 key material into the right primitives.
    func testV6KeysParse() throws {
        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: d(Self.aliceSecB64), passphrase: nil)
        XCTAssertEqual(aliceSign.fingerprint.count, 32, "v6 fingerprint is SHA-256 (32 bytes)")
        XCTAssertEqual(hex(aliceSign.fingerprint), Self.aliceSignSubkeyFpr, "signing subkey fingerprint")

        let bobDec = try OpenPGPPacketParser.x25519DecryptionKey(fromV6SecretKey: d(Self.bobSecB64), passphrase: nil)
        XCTAssertEqual(bobDec.privateKey.count, 32, "v6 X25519 scalar is 32 bytes")
        XCTAssertEqual(bobDec.subkeyFingerprint.count, 32, "v6 subkey fingerprint is 32 bytes")

        let bobRcpt = try OpenPGPPacketParser.x25519Recipient(fromV6PublicKey: d(Self.bobPubB64))
        XCTAssertEqual(bobRcpt.subkeyPublicKey.count, 32, "v6 X25519 public point is 32 bytes")
        XCTAssertEqual(bobRcpt.subkeyID, bobDec.subkeyID, "v6 recipient/decryption key IDs match")
    }

    // Alice signs+encrypts to Bob (v6 PKESK + SEIPDv2); Bob decrypts and verifies the signing-subkey signature.
    func testV6RoundTrip() throws {
        let plaintext = Data("hello from carrierpony - v6 conformance".utf8)

        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: d(Self.aliceSecB64), passphrase: nil)
        let bobRcpt = try OpenPGPPacketParser.x25519Recipient(fromV6PublicKey: d(Self.bobPubB64))
        let envelope = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [bobRcpt], signingInfo: aliceSign, armor: false)

        let bobDec = try OpenPGPPacketParser.x25519DecryptionKey(fromV6SecretKey: d(Self.bobSecB64), passphrase: nil)
        let contents = try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
            messageData: envelope, decryptionKeys: [bobDec])
        XCTAssertEqual(contents.literalData, plaintext, "recovered plaintext must be byte-exact")

        let claimed = OpenPGPPacketParser.claimedSignerFingerprint(contents: contents)
        XCTAssertEqual(claimed, Self.aliceSignSubkeyFpr, "sender derived from v6 signing subkey")

        let aliceEd = try OpenPGPPacketParser.ed25519SigningSubkeyPublicKey(fromV6PublicKey: d(Self.alicePubB64))
        XCTAssertTrue(try OpenPGPPacketParser.verifyInlineSignature(
            contents: contents, signerEd25519PublicKey: aliceEd), "v6 inline signature must verify")
    }

    // Full 8-bit range plus one extra byte, for binary-safe handling through v6 SEIPDv2.
    func testV6BinaryPayload() throws {
        var bytes = [UInt8](0...255); bytes.append(0x2A)
        let plaintext = Data(bytes)

        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: d(Self.aliceSecB64), passphrase: nil)
        let bobRcpt = try OpenPGPPacketParser.x25519Recipient(fromV6PublicKey: d(Self.bobPubB64))
        let envelope = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [bobRcpt], signingInfo: aliceSign, armor: false)

        let bobDec = try OpenPGPPacketParser.x25519DecryptionKey(fromV6SecretKey: d(Self.bobSecB64), passphrase: nil)
        let contents = try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
            messageData: envelope, decryptionKeys: [bobDec])
        XCTAssertEqual(contents.literalData, plaintext)
    }

    // Protected (S2K usage 253) keys unlock with the passphrase and round-trip.
    func testV6ProtectedRoundTrip() throws {
        let plaintext = Data("hello from carrierpony - v6 protected".utf8)

        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(
            fromV6SecretKey: d(Self.aliceSecProtB64), passphrase: Self.v6Passphrase)
        XCTAssertEqual(hex(aliceSign.fingerprint), Self.aliceSignSubkeyFpr, "protected signing subkey fingerprint")

        let bobRcpt = try OpenPGPPacketParser.x25519Recipient(fromV6PublicKey: d(Self.bobPubB64))
        let envelope = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [bobRcpt], signingInfo: aliceSign, armor: false)

        let bobDec = try OpenPGPPacketParser.x25519DecryptionKey(
            fromV6SecretKey: d(Self.bobSecProtB64), passphrase: Self.v6Passphrase)
        let contents = try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
            messageData: envelope, decryptionKeys: [bobDec])
        XCTAssertEqual(contents.literalData, plaintext, "protected-key round-trip plaintext")

        let claimed = OpenPGPPacketParser.claimedSignerFingerprint(contents: contents)
        XCTAssertEqual(claimed, Self.aliceSignSubkeyFpr, "sender from protected signing subkey")

        let aliceEd = try OpenPGPPacketParser.ed25519SigningSubkeyPublicKey(fromV6PublicKey: d(Self.alicePubB64))
        XCTAssertTrue(try OpenPGPPacketParser.verifyInlineSignature(
            contents: contents, signerEd25519PublicKey: aliceEd), "protected-key inline signature verifies")
    }

    // A wrong passphrase must fail the AEAD tag rather than yielding a bogus key.
    func testV6ProtectedWrongPassphraseFails() throws {
        XCTAssertThrowsError(try OpenPGPPacketParser.x25519DecryptionKey(
            fromV6SecretKey: d(Self.bobSecProtB64), passphrase: "not-the-passphrase"))
    }

}
