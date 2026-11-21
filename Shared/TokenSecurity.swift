import CryptoKit
import Foundation
import Security

enum TokenConstants {
    // Preserve these identifiers so upgrades can still use existing keys and identities.
    static let keyTag = Data("com.mwielgoszewski.SecureEnclaveToken.Key".utf8)
    static let driverID = "com.mwielgoszewski.SecureEnclaveToken.SecureEnclaveTokenExtension"
}

enum TokenFailure: LocalizedError {
    case message(String)
    case security(OSStatus)

    var errorDescription: String? {
        switch self {
        case .message(let message): message
        case .security(let status):
            (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)."
        }
    }

    static func underlying(_ error: Unmanaged<CFError>?, fallback: String) -> any Error {
        if let error { return error.takeRetainedValue() as Error }
        return TokenFailure.message(fallback)
    }
}

enum KeyAuthentication: String, CaseIterable, Identifiable, Sendable {
    case userPresence, biometrics, biometryCurrentSet, devicePasscode, none

    var id: Self { self }
    var title: String {
        switch self {
        case .userPresence: "Touch ID or password"
        case .biometrics: "Touch ID"
        case .biometryCurrentSet: "Current Touch ID fingerprints"
        case .devicePasscode: "Device password"
        case .none: "No additional authentication"
        }
    }

    var flags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence: [.privateKeyUsage, .userPresence]
        case .biometrics: [.privateKeyUsage, .biometryAny]
        case .biometryCurrentSet: [.privateKeyUsage, .biometryCurrentSet]
        case .devicePasscode: [.privateKeyUsage, .devicePasscode]
        case .none: [.privateKeyUsage]
        }
    }
}

enum KeyAccessibility: String, CaseIterable, Identifiable, Sendable {
    case whenUnlocked, afterFirstUnlock

    var id: Self { self }
    var title: String { self == .whenUnlocked ? "When unlocked" : "After first unlock" }
    var value: CFString {
        self == .whenUnlocked ? kSecAttrAccessibleWhenUnlockedThisDeviceOnly : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }
}

struct StoredKey: Identifiable, Sendable {
    let id: Data
    let hardwareBacked: Bool
    var name: String { String(data: id, encoding: .utf8) ?? id.map { String(format: "%02x", $0) }.joined() }
}

enum TokenSecurity {
    static func storedKeys() throws -> [StoredKey] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw TokenFailure.security(status) }
        guard let attributes = result as? [[String: Any]] else {
            throw TokenFailure.message("Could not read the stored key list.")
        }
        return storedKeys(from: attributes)
    }

    static func storedKeys(from attributes: [[String: Any]]) -> [StoredKey] {
        var seen = Set<Data>()
        return attributes.compactMap { item in
            guard let tag = item[kSecAttrApplicationTag as String] as? Data, !tag.isEmpty else { return nil }
            let tokenID = item[kSecAttrTokenID as String] as? String
            // Published CryptoTokenKit keys are aliases, not additional stored keys.
            guard tokenID == nil || tokenID == kSecAttrTokenIDSecureEnclave as String,
                  seen.insert(tag).inserted else { return nil }
            return StoredKey(id: tag, hardwareBacked: tokenID == kSecAttrTokenIDSecureEnclave as String)
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    static func keyQuery(tag: Data = TokenConstants.keyTag) -> [String: Any] {
        [kSecClass as String: kSecClassKey,
         kSecAttrApplicationTag as String: tag,
         kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
    }

    static func loadKey(tag: Data = TokenConstants.keyTag) throws -> SecKey? {
        var query = keyQuery(tag: tag)
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw TokenFailure.security(status) }
        guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw TokenFailure.message("The keychain returned an invalid key.")
        }
        // Security returns an opaque CFTypeRef; its type ID was checked above.
        return (item as! SecKey)
    }

    static func requireKey(tag: Data = TokenConstants.keyTag) throws -> SecKey {
        guard let key = try loadKey(tag: tag) else {
            throw TokenFailure.message("Generate a Secure Enclave key first.")
        }
        guard isHardwareBacked(key) else {
            throw TokenFailure.message("The existing key is a legacy software key. It cannot be used as a Secure Enclave identity.")
        }
        return key
    }

    static func isHardwareBacked(_ key: SecKey) -> Bool {
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]
        return attributes?[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String
    }

    static func generateKey(tag: Data = TokenConstants.keyTag, accessibility: KeyAccessibility, authentication: KeyAuthentication) throws {
        guard !tag.isEmpty else { throw TokenFailure.message("Enter a nonempty key tag.") }
        guard SecureEnclave.isAvailable else {
            throw TokenFailure.message("Secure Enclave access is unavailable on this Mac.")
        }
        guard try loadKey(tag: tag) == nil else {
            throw TokenFailure.message("A key already exists. Export or use that key before deciding whether to delete it.")
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, accessibility.value, authentication.flags, &error) else {
            throw TokenFailure.underlying(error, fallback: "Could not create the key’s access policy.")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ]
        ]
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw TokenFailure.underlying(error, fallback: "Could not generate a Secure Enclave key.")
        }
    }

    static func deleteKey(tag: Data = TokenConstants.keyTag) throws {
        let status = SecItemDelete(keyQuery(tag: tag) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TokenFailure.security(status)
        }
    }

    static func publicKey(for privateKey: SecKey) throws -> SecKey {
        guard let key = SecKeyCopyPublicKey(privateKey) else {
            throw TokenFailure.message("Could not read the public key.")
        }
        return key
    }

    static func externalRepresentation(of key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) else {
            throw TokenFailure.underlying(error, fallback: "Could not export the public key.")
        }
        return data as Data
    }

    static func subjectPublicKeyInfo(_ publicKey: SecKey) throws -> Data {
        let bytes = try externalRepresentation(of: publicKey)
        guard bytes.count == 65, bytes.first == 0x04 else {
            throw TokenFailure.message("Expected an uncompressed P-256 public key.")
        }
        return try P256.Signing.PublicKey(x963Representation: bytes).derRepresentation
    }

    static func certificate(from data: Data) throws -> SecCertificate {
        var der = data
        if let pem = String(data: data, encoding: .utf8), pem.contains("-----BEGIN CERTIFICATE-----") {
            let parts = pem.components(separatedBy: "-----BEGIN CERTIFICATE-----")
            guard parts.count == 2,
                  let body = parts.last?.components(separatedBy: "-----END CERTIFICATE-----"), body.count == 2,
                  let decoded = Data(base64Encoded: body[0].filter { !$0.isWhitespace }) else {
                throw TokenFailure.message("Choose a single PEM or DER encoded certificate.")
            }
            der = decoded
        }
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw TokenFailure.message("This file does not contain a valid X.509 certificate.")
        }
        return certificate
    }

    static func validate(_ certificate: SecCertificate, matches publicKey: SecKey) throws {
        guard let certificateKey = SecCertificateCopyKey(certificate),
              try externalRepresentation(of: certificateKey) == externalRepresentation(of: publicKey) else {
            throw TokenFailure.message("The certificate does not match this key. Request a certificate using this app’s signing request.")
        }
    }
}
