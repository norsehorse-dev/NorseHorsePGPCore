// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import XCTest
@testable import NorseHorsePGPCore

/// Conformance for the v6 (RFC 9580) detached-signature path used by the
/// CarrierPony relay challenge when the identity is a v6 key.
///
/// Three proofs:
///  1. Round-trip: this core builds a v6 detached signature over a nonce and its
///     own verifier accepts it; a tampered document and a wrong signer key are
///     both rejected.
///  2. Interop: a genuine Sequoia PGP v6 detached signature (SHA-512, 32-byte
///     salt) over a fixed nonce is embedded and verified, proving the verifier is
///     hash-agile and accepts a real third-party RFC 9580 signer, not just this
///     core's own SHA-256 output.
///  3. Structure: the armored output is a well-formed PGP SIGNATURE block.
///
/// Signing keys are the genuine Sequoia v6 identity (Ed25519 signing subkey +
/// X25519 subkey). Hermetic: no external tools at runtime.
final class V6DetachedSignatureTests: XCTestCase {

    static let aliceSecB64 = "xUsGakVLdRsAAAAg32eX1mvZDdwWBqurmxhoapIkGoXE4sLoGwEwruIIwEwAmAyPdtkvDelqeOzhsOzMmzQqbd4ktFFSb2b1o/VMJoLCrAYfGwoAAAA9BYJqRUt1BYkFn6YAAwsJBwMVCggCmwECHgkiIQa4P6Pe+kF+TJHaLQl+laph9tiswCHy5nwzq/b5SHz+QQAAAAAUACAvIiN6idkiqfGYh6YCtVEjMfRywN530hHrGg3oPhk4I2eB+RIDpOxASbeHEWZ8Yr6fuqBwdDQ/hftCjKyuY81+X7/0n3+LJ93DhwkRr+Jwz78YhGyu4zOkZVR6JQVdkwrNHkFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PsKvBhMbCgAAAEAFgmpFS3UFiQWfpgADCwkHAxUKCAKZAQKbAQIeCSIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAJCuIOznbJsCKf/xU2BGECMYuh1K0RxbVSJ7PztkBz2C6TI9FxRmoFL64KRNIVmdHUC8tyEnq649Nmn/i4oIn10x6RB3zy41qC4qPMnxvM3UyXld4y/UkImnPEH4NNdDoFrXCMdLBmpFS3UZAAAAIMlZfRTSt43ytQXw0hZemGVrZX01HznGEF505kD04It4APHm4622beyZU3ZEhahXvVBPZlRj5BPlt+O86aEWN19UwqEGGBsKAAAAMgWCakVLdQWJBZ+mAAKbDCIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAFSQIBnI+mVeRxq8d/SshcdB0Ts04p9mAS7tPi1FLyzec9Rl6mAtjOG/MxEObF6aEtyZjzIs7NGmRk4MFBuXgUUImA8EiqzOSIRr1zao9NTsZ/8CYLXLSivgHmoJmRTqSBawCsdLBmpFS3UbAAAAICRvhA6C4qEX2LyGXEDQ1hIeTI96nNDwECULTrte9z1MAG2xN7yNe+kn22RGg3tljANHYI1KGUvfRJJ2nKveRuYiwsB7BhgbCgAAAMwFgmpFS3UFiQWfpgACmwKZoAYZGwoAAAApBYJqRUt1IiEGbQUdP2ik0m+6eRiWSXYx0F2IQK9RQ8X7dheLM1gC/nUAAAAA54IgZ41yJvSF4v6Og0WNQvF+hsvJNPUWMq7/lXYugOEyQ2GEfo0FMO+agBKRiZl+l0y2/JTDZ+3HPxZqk/v0jWEA8GdtQoFWlTeT3lFmLLHMqHUvgmqhFUXI8g9++iHnRpMKIiEGuD+j3vpBfkyR2i0JfpWqYfbYrMAh8uZ8M6v2+Uh8/kEAAAAAoTIg/OaxXricAeAQrMHkZUDcHMdcAsBV/jklyixLk+vJDgLdrtxYHqTCs5LR3R4lstz783VbQjGkd8jURmDhxJEpLu/yGpz3BPXY5OAgSdsFGOtVKSsl1Zx72RVZAI9hNy4C"
    static let alicePubB64 = "xioGakVLdRsAAAAg32eX1mvZDdwWBqurmxhoapIkGoXE4sLoGwEwruIIwEzCrAYfGwoAAAA9BYJqRUt1BYkFn6YAAwsJBwMVCggCmwECHgkiIQa4P6Pe+kF+TJHaLQl+laph9tiswCHy5nwzq/b5SHz+QQAAAAAUACAvIiN6idkiqfGYh6YCtVEjMfRywN530hHrGg3oPhk4I2eB+RIDpOxASbeHEWZ8Yr6fuqBwdDQ/hftCjKyuY81+X7/0n3+LJ93DhwkRr+Jwz78YhGyu4zOkZVR6JQVdkwrNHkFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PsKvBhMbCgAAAEAFgmpFS3UFiQWfpgADCwkHAxUKCAKZAQKbAQIeCSIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAJCuIOznbJsCKf/xU2BGECMYuh1K0RxbVSJ7PztkBz2C6TI9FxRmoFL64KRNIVmdHUC8tyEnq649Nmn/i4oIn10x6RB3zy41qC4qPMnxvM3UyXld4y/UkImnPEH4NNdDoFrXCM4qBmpFS3UZAAAAIMlZfRTSt43ytQXw0hZemGVrZX01HznGEF505kD04It4wqEGGBsKAAAAMgWCakVLdQWJBZ+mAAKbDCIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAFSQIBnI+mVeRxq8d/SshcdB0Ts04p9mAS7tPi1FLyzec9Rl6mAtjOG/MxEObF6aEtyZjzIs7NGmRk4MFBuXgUUImA8EiqzOSIRr1zao9NTsZ/8CYLXLSivgHmoJmRTqSBawCs4qBmpFS3UbAAAAICRvhA6C4qEX2LyGXEDQ1hIeTI96nNDwECULTrte9z1MwsB7BhgbCgAAAMwFgmpFS3UFiQWfpgACmwKZoAYZGwoAAAApBYJqRUt1IiEGbQUdP2ik0m+6eRiWSXYx0F2IQK9RQ8X7dheLM1gC/nUAAAAA54IgZ41yJvSF4v6Og0WNQvF+hsvJNPUWMq7/lXYugOEyQ2GEfo0FMO+agBKRiZl+l0y2/JTDZ+3HPxZqk/v0jWEA8GdtQoFWlTeT3lFmLLHMqHUvgmqhFUXI8g9++iHnRpMKIiEGuD+j3vpBfkyR2i0JfpWqYfbYrMAh8uZ8M6v2+Uh8/kEAAAAAoTIg/OaxXricAeAQrMHkZUDcHMdcAsBV/jklyixLk+vJDgLdrtxYHqTCs5LR3R4lstz783VbQjGkd8jURmDhxJEpLu/yGpz3BPXY5OAgSdsFGOtVKSsl1Zx72RVZAI9hNy4C"

    // Fixed nonce and a genuine Sequoia-produced v6 detached signature over it.
    // The signature block is itself base64-wrapped so it survives as one literal.
    static let seqNonce = "carrierpony-relay-challenge-nonce-v6-0001"
    static let seqDetachedSigB64 = "LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0tLS0KCndwZ0dBQnNLQUFBQUtRV0Nha1ZSRVNJaEJtMEZIVDlvcE5KdnVua1lsa2wyTWRCZGlFQ3ZVVVBGKzNZWGl6TlkKQXY1MUFBQUFBR2FsSUdwWFJOSTl4WkIvUXpkekxYelJZM3N5MGtVWWhtbkpvNUZ6WTBrVlR3RHJEYWhKRFlydgpMc3ZWeitMZ2d2RFdMNEJBc00wRVVMa1I4Qlk4VGVLSEhGYU1qYnVYRU1UalhwYkVoSldTZzg4Z01ZTTBzckhVCkd5R2tsbDlBS29kc0JRPT0KLS0tLS1FTkQgUEdQIFNJR05BVFVSRS0tLS0tCg=="

    private func d(_ b64: String) -> Data { Data(base64Encoded: b64)! }
    private func armored(_ b64: String) -> String { String(data: d(b64), encoding: .utf8)! }

    private func aliceSigningInfo() throws -> Ed25519SigningInfo {
        try OpenPGPPacketParser.ed25519SigningInfo(fromV6SecretKey: d(Self.aliceSecB64), passphrase: nil)
    }
    private func alicePublicSigningKey() throws -> [UInt8] {
        try OpenPGPPacketParser.ed25519SigningSubkeyPublicKey(fromV6PublicKey: d(Self.alicePubB64))
    }

    // 1a. Build with this core, verify with this core.
    func testV6DetachedRoundTrip() throws {
        let nonce = Data("relay-challenge-\(UUID().uuidString)".utf8)
        let sig = try OpenPGPPacketBuilder.detachedSignatureEd25519V6(over: nonce, signingInfo: try aliceSigningInfo())
        let ok = try OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: sig, over: nonce, signerV6PublicKey: try alicePublicSigningKey())
        XCTAssertTrue(ok, "core-built v6 detached signature must verify")
    }

    // 1b. A tampered document must be rejected.
    func testV6DetachedTamperRejected() throws {
        let nonce = Data("relay-challenge-tamper".utf8)
        let sig = try OpenPGPPacketBuilder.detachedSignatureEd25519V6(over: nonce, signingInfo: try aliceSigningInfo())
        let ok = try OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: sig, over: Data("relay-challenge-tampeR".utf8), signerV6PublicKey: try alicePublicSigningKey())
        XCTAssertFalse(ok, "signature over a different document must not verify")
    }

    // 1c. A wrong signer key must be rejected.
    func testV6DetachedWrongKeyRejected() throws {
        let nonce = Data("relay-challenge-wrongkey".utf8)
        let sig = try OpenPGPPacketBuilder.detachedSignatureEd25519V6(over: nonce, signingInfo: try aliceSigningInfo())
        var wrong = try alicePublicSigningKey()
        wrong[0] ^= 0xFF
        let ok = try OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: sig, over: nonce, signerV6PublicKey: wrong)
        XCTAssertFalse(ok, "verification under a corrupted key must fail")
    }

    // 2. Verify a genuine Sequoia v6 detached signature (SHA-512, 32-byte salt).
    func testVerifiesSequoiaV6DetachedSignature() throws {
        let nonce = Data(Self.seqNonce.utf8)
        let sig = armored(Self.seqDetachedSigB64)
        let ok = try OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: sig, over: nonce, signerV6PublicKey: try alicePublicSigningKey())
        XCTAssertTrue(ok, "a genuine Sequoia SHA-512 v6 detached signature must verify (hash-agility)")

        // And a tampered nonce against the Sequoia signature is rejected.
        let bad = try OpenPGPPacketParser.verifyDetachedSignatureEd25519V6(
            armored: sig, over: Data((Self.seqNonce + "x").utf8), signerV6PublicKey: try alicePublicSigningKey())
        XCTAssertFalse(bad, "Sequoia signature must not verify over a modified nonce")
    }

    // 3. Armored structure.
    func testV6DetachedArmorStructure() throws {
        let sig = try OpenPGPPacketBuilder.detachedSignatureEd25519V6(
            over: Data("x".utf8), signingInfo: try aliceSigningInfo())
        XCTAssertTrue(sig.contains("BEGIN PGP SIGNATURE"))
        XCTAssertTrue(sig.contains("END PGP SIGNATURE"))
    }
}
