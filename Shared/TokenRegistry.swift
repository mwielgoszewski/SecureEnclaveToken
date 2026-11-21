import CryptoKit
import CryptoTokenKit
import Foundation
import IOKit
import Security

// Used by both the hosting app and its CLI. Reads never create a configuration.
enum TokenRegistry {
    static var serialNumber: String? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        return IORegistryEntryCreateCFProperty(service, kIOPlatformSerialNumberKey as CFString, nil, 0)?.takeRetainedValue() as? String
    }

    static var instanceID: String {
        guard let serial = serialNumber else { return "819D11D7A8F7D609F236F529996E9F4C" }
        return SHA256.hash(data: Data(serial.utf8)).prefix(16).map { String(format: "%02X", $0) }.joined()
    }

    static var driver: TKTokenDriver.Configuration? {
        TKTokenDriver.Configuration.driverConfigurations[TokenConstants.driverID]
    }

    static func configuration(create: Bool = false) throws -> TKToken.Configuration? {
        guard let driver else { throw TokenFailure.message("The token extension is unavailable. Run a signed build and enable its extension in System Settings.") }
        if let config = driver.tokenConfigurations[instanceID] { return config }
        return create ? driver.addTokenConfiguration(for: instanceID) : nil
    }

    static func items(for tag: Data) throws -> [TKTokenKeychainItem] {
        try configuration()?.keychainItems.filter { $0.objectID as? Data == tag } ?? []
    }

    static func remove(tag: Data) throws {
        guard let config = try configuration() else { return }
        config.keychainItems = excluding(tag: tag, from: config.keychainItems)
    }

    static func excluding(tag: Data, from items: [TKTokenKeychainItem]) -> [TKTokenKeychainItem] {
        items.filter { $0.objectID as? Data != tag }
    }

    static func clear() throws {
        guard let driver else { throw TokenFailure.message("The token extension is unavailable.") }
        driver.removeTokenConfiguration(for: instanceID)
    }

    static func install(certificateData: Data, tag: Data, replace: Bool = true) throws {
        let certificate = try TokenSecurity.certificate(from: certificateData)
        let publicKey = try TokenSecurity.publicKey(for: TokenSecurity.requireKey(tag: tag))
        try TokenSecurity.validate(certificate, matches: publicKey)
        guard let tokenCertificate = TKTokenKeychainCertificate(certificate: certificate, objectID: tag),
              let tokenKey = TKTokenKeychainKey(certificate: certificate, objectID: tag) else {
            throw TokenFailure.message("Could not create an identity from this certificate.")
        }
        let bytes = try TokenSecurity.externalRepresentation(of: publicKey)
        tokenCertificate.label = SecCertificateCopySubjectSummary(certificate) as String? ?? "Secure Enclave certificate"
        tokenKey.label = "\(String(decoding: tag, as: UTF8.self)) key"
        tokenKey.canSign = true
        tokenKey.canPerformKeyExchange = true
        tokenKey.canDecrypt = false
        tokenKey.isSuitableForLogin = false
        tokenKey.applicationTag = tag
        tokenKey.keySizeInBits = 256
        tokenKey.keyType = kSecAttrKeyTypeECSECPrimeRandom as String
        tokenKey.publicKeyData = bytes
        // CryptoTokenKit uses SHA-1 as a key identifier, not as a signature algorithm.
        tokenKey.publicKeyHash = Data(Insecure.SHA1.hash(data: bytes))
        guard let config = try configuration(create: true) else { return }
        if !replace && config.keychainItems.contains(where: { $0.objectID as? Data == tag }) {
            throw TokenFailure.message("This key already has a published certificate. Remove it first or use --replace.")
        }
        config.keychainItems = excluding(tag: tag, from: config.keychainItems) + [tokenKey, tokenCertificate]
    }
}
