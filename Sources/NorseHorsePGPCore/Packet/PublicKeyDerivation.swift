import Foundation

// Derive a transferable PUBLIC key from a transferable SECRET key by stripping
// the (unencrypted) public portions out of the key/subkey packets and keeping
// the User ID and signature packets verbatim. No passphrase is needed: the
// public material at the front of a secret-key packet is never encrypted.
//
// This lets CarrierPony import an existing key while keeping the secret key in
// its original (possibly passphrase-protected) form — the public key it needs to
// register and hand to contacts is derived here, and the original signatures
// (self-sig, subkey binding) are preserved so gpg and other tools accept it.

public extension OpenPGPPacketParser {

    /// Convert a transferable secret key (armored or raw) into an armored
    /// transferable public key. Supports v4 Ed25519 (EdDSA, algo 22) primaries
    /// with Cv25519 (ECDH, algo 18) subkeys, and v6 keys of any algorithm.
    static func transferablePublicKey(fromSecretKey data: Data) throws -> String {
        let packets = try parsePackets(data: [UInt8](data))
        var out: [UInt8] = []

        for packet in packets {
            switch packet.tag {
            case 5:  // Secret-Key -> Public-Key
                let pub = try publicPortion(ofKeyBody: packet.body)
                out.append(contentsOf: newFormatPacket(tag: 6, body: pub))
            case 7:  // Secret-Subkey -> Public-Subkey
                let pub = try publicPortion(ofKeyBody: packet.body)
                out.append(contentsOf: newFormatPacket(tag: 14, body: pub))
            case 13, 2:  // User ID, Signature: keep verbatim
                out.append(contentsOf: newFormatPacket(tag: packet.tag, body: packet.body))
            default:
                break  // drop trust packets, etc.
            }
        }

        return armorPublicKey(Data(out))
    }

    // MARK: - Public-portion parsing

    private static func publicPortion(ofKeyBody body: [UInt8]) throws -> [UInt8] {
        // v6: version(1) | creation(4) | algorithm(1) | material length(4) |
        // material. The length is explicit, so any algorithm is carried over
        // as it is (Ed25519, X25519, ML-KEM-768 + X25519).
        if body.first == 6 {
            guard body.count > 10 else { throw PacketParserError.invalidPacket("Truncated v6 key packet") }
            let materialLength = Int(body[6]) << 24 | Int(body[7]) << 16 | Int(body[8]) << 8 | Int(body[9])
            let end = 10 + materialLength
            guard materialLength > 0, end <= body.count else {
                throw PacketParserError.invalidPacket("Truncated v6 key material")
            }
            return Array(body[0..<end])
        }
        var off = 0
        guard body.count > 6, body[0] == 4 else {
            throw PacketParserError.invalidPacket("Unsupported key packet (v4 only)")
        }
        off += 1        // version
        off += 4        // creation time
        let algo = body[off]; off += 1

        guard algo == 22 || algo == 18 else {
            throw PacketParserError.invalidPacket("Unsupported key algorithm \(algo); need Ed25519/Cv25519")
        }

        // Curve OID
        guard off < body.count else { throw PacketParserError.invalidPacket("Truncated OID") }
        let oidLen = Int(body[off]); off += 1
        guard off + oidLen <= body.count else { throw PacketParserError.invalidPacket("Truncated OID") }
        off += oidLen

        // Public key MPI (point)
        guard off + 2 <= body.count else { throw PacketParserError.invalidPacket("Truncated MPI") }
        let bits = Int(body[off]) << 8 | Int(body[off + 1]); off += 2
        let mpiBytes = (bits + 7) / 8
        guard off + mpiBytes <= body.count else { throw PacketParserError.invalidPacket("Truncated MPI body") }
        off += mpiBytes

        // ECDH keys carry KDF parameters as part of their public material.
        if algo == 18 {
            guard off < body.count else { throw PacketParserError.invalidPacket("Truncated KDF params") }
            let kdfLen = Int(body[off]); off += 1
            guard off + kdfLen <= body.count else { throw PacketParserError.invalidPacket("Truncated KDF params") }
            off += kdfLen
        }

        return Array(body[0..<off])
    }

    // MARK: - Local encoders (self-contained; no dependency on the generator)

    private static func newFormatPacket(tag: UInt8, body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0xC0 | tag]
        let len = body.count
        if len < 192 {
            out.append(UInt8(len))
        } else if len < 8384 {
            let l = len - 192
            out.append(UInt8((l >> 8) + 192))
            out.append(UInt8(l & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((len >> 24) & 0xFF))
            out.append(UInt8((len >> 16) & 0xFF))
            out.append(UInt8((len >> 8) & 0xFF))
            out.append(UInt8(len & 0xFF))
        }
        out.append(contentsOf: body)
        return out
    }

    private static func armorPublicKey(_ data: Data) -> String {
        let base64 = data.base64EncodedString(options: .lineLength76Characters)
        let crc = crc24Armor(data)
        let crcB64 = Data(crc).base64EncodedString()
        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\(base64)\n=\(crcB64)\n-----END PGP PUBLIC KEY BLOCK-----"
    }

    private static func crc24Armor(_ data: Data) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 { crc ^= 0x1864CFB }
            }
        }
        crc &= 0xFFFFFF
        return [UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)]
    }
}
