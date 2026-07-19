import Foundation

// Inline-signature verification helpers.
//
// These sit on the existing parser primitives and let a consumer resolve the
// signer's public key itself, keeping the core free of keyring callbacks. They
// are the verify half of the CarrierPony messaging path; the build/encrypt half
// is buildEncryptedMessage.
//
// Requires (upstream spec Part A) that these existing symbols be public:
// DecryptedMessageContents, ParsedPacket, ParsedSignature, ParsedPublicKeyInfo,
// PacketParserError, and the static methods parseSignaturePacket,
// parseAllPublicKeys, verifyEd25519Signature.

public extension OpenPGPPacketParser {

    /// The fingerprint the inner signature claims, read from its issuer-fingerprint
    /// subpacket (type 33). Uppercase hex (40 chars for v4, 64 for v6). Returns nil
    /// if there is no tag-2 signature packet or it carries no issuer fingerprint.
    static func claimedSignerFingerprint(contents: DecryptedMessageContents) -> String? {
        guard let sigPacket = contents.innerPackets.first(where: { $0.tag == 2 }),
              let sig = try? parseSignaturePacket(body: sigPacket.body),
              let fpr = sig.issuerFingerprint else {
            return nil
        }
        return fpr.map { String(format: "%02X", $0) }.joined()
    }

    /// Extract the primary 32-byte Ed25519 public key from a public key blob.
    /// Handles v4 (algo 22: OID + MPI, optional 0x40 prefix) and v6 (algo 27:
    /// raw 32-byte material).
    static func ed25519PublicKey(fromPublicKeyData data: Data) throws -> [UInt8] {
        let keys = try parseAllPublicKeys(from: Array(data))
        guard let primary = keys.first else {
            throw PacketParserError.invalidPacket("No public key found")
        }

        if primary.version == 6 && primary.algorithm == 27 {
            return primary.keyMaterial
        }

        if primary.algorithm == 22 {
            let km = primary.keyMaterial
            var off = 0
            guard km.count > 2 else {
                throw PacketParserError.invalidPacket("V4 EdDSA key material too short")
            }
            let oidLen = Int(km[off]); off += 1
            off += oidLen
            guard off + 2 <= km.count else {
                throw PacketParserError.invalidPacket("V4 EdDSA missing public key MPI")
            }
            let qBits = Int(km[off]) << 8 | Int(km[off + 1]); off += 2
            let qBytes = (qBits + 7) / 8
            guard off + qBytes <= km.count else {
                throw PacketParserError.invalidPacket("V4 EdDSA public key MPI truncated")
            }
            var raw = Array(km[off..<(off + qBytes)])
            if raw.first == 0x40 {
                raw = Array(raw.dropFirst())
            }
            guard raw.count == 32 else {
                throw PacketParserError.invalidPacket("Ed25519 public key is \(raw.count) bytes, expected 32")
            }
            return raw
        }

        throw PacketParserError.invalidPacket(
            "Signer key is not Ed25519 (algo \(primary.algorithm), v\(primary.version))"
        )
    }

    /// Verify the inner tag-2 signature over the tag-11 literal body using the
    /// signer's 32-byte Ed25519 public key. The signed document is the literal
    /// data packet body (format byte + filename + date + content), matching what
    /// the builder signs for inline signatures.
    static func verifyInlineSignature(
        contents: DecryptedMessageContents,
        signerEd25519PublicKey: [UInt8]
    ) throws -> Bool {
        guard let sigPacket = contents.innerPackets.first(where: { $0.tag == 2 }) else {
            throw PacketParserError.invalidPacket("No signature packet in message")
        }
        guard contents.innerPackets.contains(where: { $0.tag == 11 }) else {
            throw PacketParserError.invalidPacket("No literal data packet in message")
        }
        let sig = try parseSignaturePacket(body: sigPacket.body)
        // A binary-document signature (type 0x00) is computed over the literal
        // DATA content only, not the literal packet header (format/filename/date).
        // contents.literalData is exactly that content, already destructured on
        // decrypt, so it matches what buildInlineSignaturePacket signed.
        return try verifyEd25519Signature(
            signature: sig,
            document: Array(contents.literalData),
            publicKey: signerEd25519PublicKey
        )
    }
}
