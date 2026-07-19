// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import XCTest
@testable import NorseHorsePGPCore

/// End-to-end v4 conformance for the messaging path, against genuine GnuPG 2.4.4
/// key material. Two identities (Ed25519 signing primary + Cv25519 encryption
/// subkey, unprotected) are exported binary and base64-embedded. Because they are
/// real gpg keys, these tests prove the v4 extractors parse actual GnuPG output,
/// and that build -> open round-trips with a signature-derived sender.
/// Hermetic: no gpg at runtime.
final class V4ConformanceTests: XCTestCase {

    static let aliceFpr = "B671D9A8B401BB207C264787A18FB667413300FD"
    static let bobFpr   = "61D27B04E1E90899E8D162824891888765D64C51"
    static let aliceSecB64 = "lFgEakR4VBYJKwYBBAHaRw8BAQdAnznJbtIY8Bs9aN2/4mC9DkQMR5dA8YHjtCjUExtdGvgAAQCnCHFJweSajt3G37loPYhdCa7mhFwxl1PccEV6/ywPvhCXtB5hbGljZSA8YWxpY2VAY2FycmllcnBvbnkudGVzdD6IkwQTFgoAOxYhBLZx2ai0AbsgfCZHh6GPtmdBMwD9BQJqRHhUAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEKGPtmdBMwD9H78A/3yQdCMjIkhFr6/kwhazMIueOJmDKreaELNLSgNgPpzMAQDmfsjO8BddtXxtfYYfnScb7CoIPooO1pNVFUSlNJ9QAJxdBGpEeFQSCisGAQQBl1UBBQEBB0D2H4y+g5gcKfgaw9W4Z7XEqD014M80nkoY8OUfkkRGOgMBCAcAAP9ZOexF0/evyEbRxxm36vjIg4Zc8kHjYrWOcxHxG9WTYBPTiHgEGBYKACAWIQS2cdmotAG7IHwmR4ehj7ZnQTMA/QUCakR4VAIbDAAKCRChj7ZnQTMA/UAYAQDWJvUc1v7jjTxJA7dSTZoOC0HVUhZ3bK2gjYrZ+Jkb3gEArbSGVO/3UwsI7sJisCOYUHTfZv6Q4XUXq7j1Bzu9zgc="
    static let alicePubB64 = "mDMEakR4VBYJKwYBBAHaRw8BAQdAnznJbtIY8Bs9aN2/4mC9DkQMR5dA8YHjtCjUExtdGvi0HmFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PoiTBBMWCgA7FiEEtnHZqLQBuyB8JkeHoY+2Z0EzAP0FAmpEeFQCGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQoY+2Z0EzAP0fvwD/fJB0IyMiSEWvr+TCFrMwi544mYMqt5oQs0tKA2A+nMwBAOZ+yM7wF121fG19hh+dJxvsKgg+ig7Wk1UVRKU0n1AAuDgEakR4VBIKKwYBBAGXVQEFAQEHQPYfjL6DmBwp+BrD1bhntcSoPTXgzzSeShjw5R+SREY6AwEIB4h4BBgWCgAgFiEEtnHZqLQBuyB8JkeHoY+2Z0EzAP0FAmpEeFQCGwwACgkQoY+2Z0EzAP1AGAEA1ib1HNb+4408SQO3Uk2aDgtB1VIWd2ytoI2K2fiZG94BAK20hlTv91MLCO7CYrAjmFB032b+kOF1F6u49Qc7vc4H"
    static let bobSecB64 = "lFgEakR4VBYJKwYBBAHaRw8BAQdAKcGxRPM6atQb5K6tQv+XHxBSXyXwWBjNkBzsW+Ddlf4AAP45Tbo3jwG7Tmpp2L0xN6f99yVVSXMorIWukcoIoP0+sRCltBpib2IgPGJvYkBjYXJyaWVycG9ueS50ZXN0PoiTBBMWCgA7FiEEYdJ7BOHpCJno0WKCSJGIh2XWTFEFAmpEeFQCGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQSJGIh2XWTFHBlgEA6iDEiZ/hxnV4r19ruAjOdrZic7Zi+R8y2LGT+2dUi0MBAJYgRZTWAkSKm5DuCcV2Vp0pJNF25EvUsW6vu5xkVsYInF0EakR4VBIKKwYBBAGXVQEFAQEHQBtEr1ZnxhJhb5ICeVeaPx1W2RA/PEc80vvoVU/0LS8SAwEIBwAA/1VL2Ab2l90G6nDyFaNuRz8WqyNTSBjRU/Q4la/zcjcYD8SIeAQYFgoAIBYhBGHSewTh6QiZ6NFigkiRiIdl1kxRBQJqRHhUAhsMAAoJEEiRiIdl1kxRPawBANPE0wdUKnfk6jxnxCEql4O+mhDiFAeGKgRKEQSQJAU2AQCaTw+EU5x+TIKB2cYJnk8uxYCwz60fxhP7s1sgMAlZCA=="
    static let bobPubB64 = "mDMEakR4VBYJKwYBBAHaRw8BAQdAKcGxRPM6atQb5K6tQv+XHxBSXyXwWBjNkBzsW+Ddlf60GmJvYiA8Ym9iQGNhcnJpZXJwb255LnRlc3Q+iJMEExYKADsWIQRh0nsE4ekImejRYoJIkYiHZdZMUQUCakR4VAIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBIkYiHZdZMUcGWAQDqIMSJn+HGdXivX2u4CM52tmJztmL5HzLYsZP7Z1SLQwEAliBFlNYCRIqbkO4JxXZWnSkk0XbkS9Sxbq+7nGRWxgi4OARqRHhUEgorBgEEAZdVAQUBAQdAG0SvVmfGEmFvkgJ5V5o/HVbZED88RzzS++hVT/QtLxIDAQgHiHgEGBYKACAWIQRh0nsE4ekImejRYoJIkYiHZdZMUQUCakR4VAIbDAAKCRBIkYiHZdZMUT2sAQDTxNMHVCp35Oo8Z8QhKpeDvpoQ4hQHhioEShEEkCQFNgEAmk8PhFOcfkyCgdnGCZ5PLsWAsM+tH8YT+7NbIDAJWQg="

    private func d(_ b64: String) -> Data { Data(base64Encoded: b64)! }
    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02X", $0) }.joined() }

    // Extractors parse genuine gpg v4 key material into the right primitives.
    func testV4KeysParse() throws {
        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: d(Self.aliceSecB64), passphrase: nil)
        XCTAssertEqual(hex(aliceSign.fingerprint), Self.aliceFpr, "signing key fingerprint")

        let bobDec = try OpenPGPPacketParser.cv25519DecryptionKey(fromSecretKey: d(Self.bobSecB64), passphrase: nil)
        XCTAssertEqual(bobDec.privateKey.count, 32, "Cv25519 scalar is 32 bytes")

        let bobRcpt = try OpenPGPPacketParser.cv25519Recipient(fromPublicKey: d(Self.bobPubB64))
        XCTAssertEqual(bobRcpt.subkeyPublicKey.count, 32, "Cv25519 public point is 32 bytes")
    }

    // Alice signs+encrypts to Bob; Bob decrypts, recovers plaintext, and verifies Alice's signature.
    func testRoundTrip() throws {
        let plaintext = Data("hello from carrierpony - v4 conformance".utf8)

        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: d(Self.aliceSecB64), passphrase: nil)
        let bobRcpt = try OpenPGPPacketParser.cv25519Recipient(fromPublicKey: d(Self.bobPubB64))
        let envelope = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [bobRcpt], signingInfo: aliceSign, armor: false)

        let bobDec = try OpenPGPPacketParser.cv25519DecryptionKey(fromSecretKey: d(Self.bobSecB64), passphrase: nil)
        let contents = try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
            messageData: envelope, decryptionKeys: [bobDec])
        XCTAssertEqual(contents.literalData, plaintext, "recovered plaintext must be byte-exact")

        let claimed = OpenPGPPacketParser.claimedSignerFingerprint(contents: contents)
        XCTAssertEqual(claimed, Self.aliceFpr, "sender derived from signature")

        let aliceEd = try OpenPGPPacketParser.ed25519PublicKey(fromPublicKeyData: d(Self.alicePubB64))
        XCTAssertTrue(try OpenPGPPacketParser.verifyInlineSignature(
            contents: contents, signerEd25519PublicKey: aliceEd), "inline signature must verify")
    }

    // Full 8-bit range plus one extra byte, for binary-safe handling.
    func testBinaryPayload() throws {
        var bytes = [UInt8](0...255); bytes.append(0x2A)
        let plaintext = Data(bytes)

        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: d(Self.aliceSecB64), passphrase: nil)
        let bobRcpt = try OpenPGPPacketParser.cv25519Recipient(fromPublicKey: d(Self.bobPubB64))
        let envelope = try OpenPGPPacketBuilder.buildEncryptedMessage(
            plaintext: plaintext, recipients: [bobRcpt], signingInfo: aliceSign, armor: false)

        let bobDec = try OpenPGPPacketParser.cv25519DecryptionKey(fromSecretKey: d(Self.bobSecB64), passphrase: nil)
        let contents = try OpenPGPPacketParser.decryptMessageReturningInnerPackets(
            messageData: envelope, decryptionKeys: [bobDec])
        XCTAssertEqual(contents.literalData, plaintext)
    }

    // Detached signature (relay-challenge path) emits a well-formed armored block.
    func testDetachedSignatureIsArmored() throws {
        let aliceSign = try OpenPGPPacketParser.ed25519SigningInfo(fromSecretKey: d(Self.aliceSecB64), passphrase: nil)
        let sig = try OpenPGPPacketBuilder.detachedSignatureEd25519(over: Data("challenge-nonce".utf8), signingInfo: aliceSign)
        XCTAssertTrue(sig.contains("BEGIN PGP SIGNATURE"))
        XCTAssertTrue(sig.contains("END PGP SIGNATURE"))
    }

}
