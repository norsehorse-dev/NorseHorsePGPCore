// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 NorseHorse

import XCTest
@testable import NorseHorsePGPCore

/// Version-detection conformance for openPGPKeyVersion(from:). Feeds it genuine
/// key material from three independent OpenPGP stacks and asserts the reported
/// version: real GnuPG 2.4.4 keys report v4, an independent RFC 9580 encoder and
/// Sequoia PGP both report v6. This is the classifier the CarrierPony adapter
/// uses to route to the v4 vs v6 extractor set, so it is proven on the same key
/// families the messaging path round-trips against. Hermetic: no external tools.
final class KeyVersionTests: XCTestCase {

    // Real gpg 2.4.4 v4 (Ed25519 signing primary + Cv25519 encryption subkey).
    static let v4PubB64 = "mDMEakR4VBYJKwYBBAHaRw8BAQdAnznJbtIY8Bs9aN2/4mC9DkQMR5dA8YHjtCjUExtdGvi0HmFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PoiTBBMWCgA7FiEEtnHZqLQBuyB8JkeHoY+2Z0EzAP0FAmpEeFQCGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQoY+2Z0EzAP0fvwD/fJB0IyMiSEWvr+TCFrMwi544mYMqt5oQs0tKA2A+nMwBAOZ+yM7wF121fG19hh+dJxvsKgg+ig7Wk1UVRKU0n1AAuDgEakR4VBIKKwYBBAGXVQEFAQEHQPYfjL6DmBwp+BrD1bhntcSoPTXgzzSeShjw5R+SREY6AwEIB4h4BBgWCgAgFiEEtnHZqLQBuyB8JkeHoY+2Z0EzAP0FAmpEeFQCGwwACgkQoY+2Z0EzAP1AGAEA1ib1HNb+4408SQO3Uk2aDgtB1VIWd2ytoI2K2fiZG94BAK20hlTv91MLCO7CYrAjmFB032b+kOF1F6u49Qc7vc4H"
    static let v4SecB64 = "lFgEakR4VBYJKwYBBAHaRw8BAQdAnznJbtIY8Bs9aN2/4mC9DkQMR5dA8YHjtCjUExtdGvgAAQCnCHFJweSajt3G37loPYhdCa7mhFwxl1PccEV6/ywPvhCXtB5hbGljZSA8YWxpY2VAY2FycmllcnBvbnkudGVzdD6IkwQTFgoAOxYhBLZx2ai0AbsgfCZHh6GPtmdBMwD9BQJqRHhUAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEKGPtmdBMwD9H78A/3yQdCMjIkhFr6/kwhazMIueOJmDKreaELNLSgNgPpzMAQDmfsjO8BddtXxtfYYfnScb7CoIPooO1pNVFUSlNJ9QAJxdBGpEeFQSCisGAQQBl1UBBQEBB0D2H4y+g5gcKfgaw9W4Z7XEqD014M80nkoY8OUfkkRGOgMBCAcAAP9ZOexF0/evyEbRxxm36vjIg4Zc8kHjYrWOcxHxG9WTYBPTiHgEGBYKACAWIQS2cdmotAG7IHwmR4ehj7ZnQTMA/QUCakR4VAIbDAAKCRChj7ZnQTMA/UAYAQDWJvUc1v7jjTxJA7dSTZoOC0HVUhZ3bK2gjYrZ+Jkb3gEArbSGVO/3UwsI7sJisCOYUHTfZv6Q4XUXq7j1Bzu9zgc="

    // Independent RFC 9580 encoder v6 (certify primary + Ed25519 sign subkey + X25519).
    static let v6PubB64 = "xioGZ3SuIBsAAAAgzM6zmkTVUuZaIuHPheCue9GNSP574ZH2ZztAdZDp5XXOKgZndK4hGwAAACDP+hoZjeFTg4lKiy4i1pEwqiaUiQXhGJdwvfCX6UMQcc4qBmd0riIZAAAAIOL4w0VzDjCdnN/2ku4ZLf96H9CqyuoRjtSz8ShzgxxA"
    static let v6SecB64 = "xUsGZ3SuIBsAAAAgzM6zmkTVUuZaIuHPheCue9GNSP574ZH2ZztAdZDp5XUA4PCtJftYi0slahoM96JiNtxL2mPzlzFkyRNPdIkbVmHHSwZndK4hGwAAACDP+hoZjeFTg4lKiy4i1pEwqiaUiQXhGJdwvfCX6UMQcQAe1S8EMM/RV6M7Jb27z2RoQQLyrKW+mq3HIiT+NPXPMcdLBmd0riIZAAAAIOL4w0VzDjCdnN/2ku4ZLf96H9CqyuoRjtSz8ShzgxxAAIAQq21e7LGtbTYDc+456FUH8SSyzJdvEtQekIsusQNg"

    // Sequoia PGP v6 (Profile.RFC9580), third-party provenance.
    static let seqPubB64 = "xioGakVLdRsAAAAg32eX1mvZDdwWBqurmxhoapIkGoXE4sLoGwEwruIIwEzCrAYfGwoAAAA9BYJqRUt1BYkFn6YAAwsJBwMVCggCmwECHgkiIQa4P6Pe+kF+TJHaLQl+laph9tiswCHy5nwzq/b5SHz+QQAAAAAUACAvIiN6idkiqfGYh6YCtVEjMfRywN530hHrGg3oPhk4I2eB+RIDpOxASbeHEWZ8Yr6fuqBwdDQ/hftCjKyuY81+X7/0n3+LJ93DhwkRr+Jwz78YhGyu4zOkZVR6JQVdkwrNHkFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PsKvBhMbCgAAAEAFgmpFS3UFiQWfpgADCwkHAxUKCAKZAQKbAQIeCSIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAJCuIOznbJsCKf/xU2BGECMYuh1K0RxbVSJ7PztkBz2C6TI9FxRmoFL64KRNIVmdHUC8tyEnq649Nmn/i4oIn10x6RB3zy41qC4qPMnxvM3UyXld4y/UkImnPEH4NNdDoFrXCM4qBmpFS3UZAAAAIMlZfRTSt43ytQXw0hZemGVrZX01HznGEF505kD04It4wqEGGBsKAAAAMgWCakVLdQWJBZ+mAAKbDCIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAFSQIBnI+mVeRxq8d/SshcdB0Ts04p9mAS7tPi1FLyzec9Rl6mAtjOG/MxEObF6aEtyZjzIs7NGmRk4MFBuXgUUImA8EiqzOSIRr1zao9NTsZ/8CYLXLSivgHmoJmRTqSBawCs4qBmpFS3UbAAAAICRvhA6C4qEX2LyGXEDQ1hIeTI96nNDwECULTrte9z1MwsB7BhgbCgAAAMwFgmpFS3UFiQWfpgACmwKZoAYZGwoAAAApBYJqRUt1IiEGbQUdP2ik0m+6eRiWSXYx0F2IQK9RQ8X7dheLM1gC/nUAAAAA54IgZ41yJvSF4v6Og0WNQvF+hsvJNPUWMq7/lXYugOEyQ2GEfo0FMO+agBKRiZl+l0y2/JTDZ+3HPxZqk/v0jWEA8GdtQoFWlTeT3lFmLLHMqHUvgmqhFUXI8g9++iHnRpMKIiEGuD+j3vpBfkyR2i0JfpWqYfbYrMAh8uZ8M6v2+Uh8/kEAAAAAoTIg/OaxXricAeAQrMHkZUDcHMdcAsBV/jklyixLk+vJDgLdrtxYHqTCs5LR3R4lstz783VbQjGkd8jURmDhxJEpLu/yGpz3BPXY5OAgSdsFGOtVKSsl1Zx72RVZAI9hNy4C"
    static let seqSecB64 = "xUsGakVLdRsAAAAg32eX1mvZDdwWBqurmxhoapIkGoXE4sLoGwEwruIIwEwAmAyPdtkvDelqeOzhsOzMmzQqbd4ktFFSb2b1o/VMJoLCrAYfGwoAAAA9BYJqRUt1BYkFn6YAAwsJBwMVCggCmwECHgkiIQa4P6Pe+kF+TJHaLQl+laph9tiswCHy5nwzq/b5SHz+QQAAAAAUACAvIiN6idkiqfGYh6YCtVEjMfRywN530hHrGg3oPhk4I2eB+RIDpOxASbeHEWZ8Yr6fuqBwdDQ/hftCjKyuY81+X7/0n3+LJ93DhwkRr+Jwz78YhGyu4zOkZVR6JQVdkwrNHkFsaWNlIDxhbGljZUBjYXJyaWVycG9ueS50ZXN0PsKvBhMbCgAAAEAFgmpFS3UFiQWfpgADCwkHAxUKCAKZAQKbAQIeCSIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAJCuIOznbJsCKf/xU2BGECMYuh1K0RxbVSJ7PztkBz2C6TI9FxRmoFL64KRNIVmdHUC8tyEnq649Nmn/i4oIn10x6RB3zy41qC4qPMnxvM3UyXld4y/UkImnPEH4NNdDoFrXCMdLBmpFS3UZAAAAIMlZfRTSt43ytQXw0hZemGVrZX01HznGEF505kD04It4APHm4622beyZU3ZEhahXvVBPZlRj5BPlt+O86aEWN19UwqEGGBsKAAAAMgWCakVLdQWJBZ+mAAKbDCIhBrg/o976QX5MkdotCX6VqmH22KzAIfLmfDOr9vlIfP5BAAAAAFSQIBnI+mVeRxq8d/SshcdB0Ts04p9mAS7tPi1FLyzec9Rl6mAtjOG/MxEObF6aEtyZjzIs7NGmRk4MFBuXgUUImA8EiqzOSIRr1zao9NTsZ/8CYLXLSivgHmoJmRTqSBawCsdLBmpFS3UbAAAAICRvhA6C4qEX2LyGXEDQ1hIeTI96nNDwECULTrte9z1MAG2xN7yNe+kn22RGg3tljANHYI1KGUvfRJJ2nKveRuYiwsB7BhgbCgAAAMwFgmpFS3UFiQWfpgACmwKZoAYZGwoAAAApBYJqRUt1IiEGbQUdP2ik0m+6eRiWSXYx0F2IQK9RQ8X7dheLM1gC/nUAAAAA54IgZ41yJvSF4v6Og0WNQvF+hsvJNPUWMq7/lXYugOEyQ2GEfo0FMO+agBKRiZl+l0y2/JTDZ+3HPxZqk/v0jWEA8GdtQoFWlTeT3lFmLLHMqHUvgmqhFUXI8g9++iHnRpMKIiEGuD+j3vpBfkyR2i0JfpWqYfbYrMAh8uZ8M6v2+Uh8/kEAAAAAoTIg/OaxXricAeAQrMHkZUDcHMdcAsBV/jklyixLk+vJDgLdrtxYHqTCs5LR3R4lstz783VbQjGkd8jURmDhxJEpLu/yGpz3BPXY5OAgSdsFGOtVKSsl1Zx72RVZAI9hNy4C"

    private func d(_ b64: String) -> Data { Data(base64Encoded: b64)! }

    func testV4KeysReportVersion4() {
        XCTAssertEqual(OpenPGPPacketParser.openPGPKeyVersion(from: d(Self.v4PubB64)), 4)
        XCTAssertEqual(OpenPGPPacketParser.openPGPKeyVersion(from: d(Self.v4SecB64)), 4)
    }

    func testV6EncoderKeysReportVersion6() {
        XCTAssertEqual(OpenPGPPacketParser.openPGPKeyVersion(from: d(Self.v6PubB64)), 6)
        XCTAssertEqual(OpenPGPPacketParser.openPGPKeyVersion(from: d(Self.v6SecB64)), 6)
    }

    func testSequoiaV6KeysReportVersion6() {
        XCTAssertEqual(OpenPGPPacketParser.openPGPKeyVersion(from: d(Self.seqPubB64)), 6)
        XCTAssertEqual(OpenPGPPacketParser.openPGPKeyVersion(from: d(Self.seqSecB64)), 6)
    }

    func testGarbageReturnsNil() {
        XCTAssertNil(OpenPGPPacketParser.openPGPKeyVersion(from: Data([0x00, 0x01, 0x02, 0x03])))
        XCTAssertNil(OpenPGPPacketParser.openPGPKeyVersion(from: Data()))
    }
}
