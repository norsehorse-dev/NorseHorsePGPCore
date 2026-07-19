import Foundation

// A passphrase-sealed box: symmetric OpenPGP encryption of arbitrary bytes under
// a passphrase (S2K-derived key). Public wrapper over the internal
// SymmetricEncryption, so apps depending only on NorseHorsePGPCore can protect small
// secrets — e.g. an identity backup — without a recipient key.
//
// `seal` returns an ASCII-armored OpenPGP message; `open` reverses it. There is
// no passphrase recovery: a lost passphrase means the contents are unrecoverable.

public enum PassphraseBox {

    /// Encrypt `plaintext` under `passphrase`, returning an armored OpenPGP message.
    public static func seal(_ plaintext: Data, passphrase: String) throws -> String {
        try SymmetricEncryption.encryptArmored(plaintext: Array(plaintext), passphrase: passphrase)
    }

    /// Decrypt an armored message produced by `seal` using `passphrase`.
    public static func open(_ armored: String, passphrase: String) throws -> Data {
        Data(try SymmetricEncryption.decryptArmored(armored: armored, passphrase: passphrase))
    }
}
