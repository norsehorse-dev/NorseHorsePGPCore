import Foundation

// Public entry point for generating a v4 messaging identity: an Ed25519 signing
// primary with a Cv25519 encryption subkey, in a standard OpenPGP v4 transferable
// key (GnuPG-compatible). Wraps the internal Ed25519KeyGenerator so apps that
// depend only on NorseHorsePGPCore (like CarrierPony) can create identities without
// reaching into module internals.
//
// The produced secret key is unprotected (no passphrase); protecting it at rest
// is the caller's responsibility (e.g. the Keychain).

public struct GeneratedIdentity: Sendable {
    /// Uppercase 40-hex primary key fingerprint.
    public let fingerprint: String
    /// Serialized OpenPGP transferable secret key bytes.
    public let secretKey: Data
    /// ASCII-armored public key.
    public let armoredPublicKey: String
    /// ASCII-armored secret key (for export/backup, if the app wants it).
    public let armoredSecretKey: String
}

public enum OpenPGPKeyGenerator {

    /// Generate a fresh v4 Ed25519 + Cv25519 identity. `name` and `email` populate
    /// the User ID; they are cosmetic — the fingerprint is the real identity.
    public static func generateV4Identity(name: String, email: String) throws -> GeneratedIdentity {
        let result = try Ed25519KeyGenerator.generate(
            name: name,
            email: email,
            passphrase: nil,
            expirationInterval: nil
        )
        return GeneratedIdentity(
            fingerprint: result.fingerprint.uppercased(),
            secretKey: result.privateKeyData,
            armoredPublicKey: result.armoredPublicKey,
            armoredSecretKey: result.armoredPrivateKey
        )
    }
}
