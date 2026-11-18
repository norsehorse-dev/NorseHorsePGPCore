import Foundation

// Detached-signature verification: the verify counterpart to
// detachedSignatureEd25519. Given an armored OpenPGP Ed25519 detached signature,
// the signed document, and the signer's armored public key, confirm the
// signature. Wraps the existing internal dearmor / parsePackets /
// parseSignaturePacket / verifyEd25519Signature primitives so app code can
// authenticate a message's sender against a known key without pulling in packet
// parsing itself (used by CarrierPony group messaging).

public extension OpenPGPPacketParser {

    static func verifyDetachedEd25519(
        armoredSignature: String,
        over document: Data,
        signerArmoredPublicKey: String
    ) throws -> Bool {
        let sigBytes = try dearmor(armoredSignature)
        let packets = try parsePackets(data: Array(sigBytes))
        guard let sigPacket = packets.first(where: { $0.tag == 2 }) else {
            throw PacketParserError.invalidPacket("No signature packet in detached signature")
        }
        let signature = try parseSignaturePacket(body: sigPacket.body)
        let keyBytes = try dearmor(signerArmoredPublicKey)
        // An identity imported from another app can sign with a signing subkey.
        // A signature that names such a subkey verifies under it, and only when
        // the subkey is bound to the primary key and has signed it back.
        // Anything else verifies under the primary key, as before.
        let signerKey: [UInt8]
        if let issuer = signature.issuerFingerprint,
           let primary = keyFingerprints(inPublicKey: Data(keyBytes)).first, issuer != primary,
           isBoundSigner(subkeyFingerprint: issuer, inPublicKey: Data(keyBytes)) {
            signerKey = try ed25519PublicKey(fromPublicKeyData: Data(keyBytes), keyFingerprint: issuer)
        } else {
            signerKey = try ed25519PublicKey(fromPublicKeyData: Data(keyBytes))
        }
        return try verifyEd25519Signature(
            signature: signature,
            document: Array(document),
            publicKey: signerKey
        )
    }
}
