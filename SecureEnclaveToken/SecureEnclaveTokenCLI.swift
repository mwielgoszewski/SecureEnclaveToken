//
//  SecureEnclaveTokenCLI.swift
//  SecureEnclaveToken
//
//  Created by Marcin Wielgoszewski on 9/25/22.
//

import Foundation
import ArgumentParser
import CertificateSigningRequest
import CryptoTokenKit
import CryptoKit

struct TokenConfiguration: Codable {
    var keys: [Data]
}

struct SecureEnclaveTokenCLI: ParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "SecureEnclaveToken cli",
        abstract: "A utility for managing secure enclave keys and tokens.",
        subcommands: [New.self, Destroy.self, Req.self, Pub.self, Keys.self, Token.self]
    )
}

struct Options: ParsableArguments {
    @Argument(help: "Private tag of the key.", transform: ({return $0.data(using: .utf8)!})) var key: Data
}

extension SecureEnclaveTokenCLI {
    struct New: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Generate a new secure enclave backed key."
        )

        enum Require: String, ExpressibleByArgument {
            case none, userPresence, biometryAny, biometryCurrentSet, devicePasscode
        }

        enum Availability: String, ExpressibleByArgument {
            case whenUnlocked, afterFirstUnlock
        }

        @OptionGroup var options: Options
        @Option(help: "Possible values: none, userPresence, biometryAny, biometryCurrentSet, or devicePasscode") var require: Require = .none
        @Option(help: "Possible values: whenUnlocked or afterFirstUnlock") var available: Availability = .afterFirstUnlock

        mutating func run() throws {
            let keyExists = loadSecureEnclaveKey(tag: options.key)

            guard keyExists == nil else {
                print("Key \(String(data: options.key, encoding: .utf8) ?? "") already exists, destroy it before generating a new one.")
                throw ExitCode.failure
            }

            var flags: SecAccessControlCreateFlags

            switch require {
            case .userPresence:
                flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.userPresence]
            case .devicePasscode:
                flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.devicePasscode]
            case .biometryAny:
                flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.biometryAny]
            case .biometryCurrentSet:
                flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.biometryCurrentSet]
            case .none:
                flags = [SecAccessControlCreateFlags.privateKeyUsage]
            }

            var accessibility: CFString
            switch available {
            case .whenUnlocked:
                accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlock:
                accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }

            _ = generateKeyInEnclave(tag: options.key, accessibility: accessibility, flags: flags)
        }
    }

    struct Destroy: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Destroy a key in the secure enclave."
        )

        @OptionGroup var options: Options

        mutating func run() throws {
            guard let tokenConfig = loadTokenConfig() else {
                print("Could not load token configuration.")
                throw ExitCode.failure
            }
            guard loadSecureEnclaveKey(tag: options.key) != nil else {
                print("Key \(String(data: options.key, encoding: .utf8) ?? "") not found")
                throw ExitCode.failure
            }
            guard deleteSecureEnclaveKey(tag: options.key) else {
                print("Failed to delete key.")
                throw ExitCode.failure
            }
            var config = try? JSONDecoder().decode(TokenConfiguration.self, from: tokenConfig.configurationData ?? Data())
            config?.keys.removeAll(where: {$0 == options.key})
            tokenConfig.configurationData = try? JSONEncoder().encode(config)
            print("Successfully deleted key.")
        }
    }

    struct Req: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Generate a certificate signing request for a given key."
        )

        @OptionGroup var options: Options
        @Option(name: [.customLong("cn", withSingleDash: true)], help: "Common Name (eg, fully qualified host name)") var commonName: String?
        @Option(name: [.customShort("o")], help: "Organization Name (eg, company)") var organizationName: String?
        @Option(name: [.customLong("ou", withSingleDash: true)], help: "Organizational Unit Name (eg, section)") var organizationUnitName: String?
        @Option(name: [.customShort("c")], help: "Country Name (2 letter code)") var countryName: String?
        @Option(name: [.customLong("st", withSingleDash: true)], help: "State or Province Name (full name)") var stateOrProvinceName: String?
        @Option(name: [.customShort("l")], help: "Locality Name (eg, city)") var localityName: String?
        @Option(name: [.customLong("email", withSingleDash: true)], help: "Email Address") var emailAddress: String?
        @Option(name: [.customShort("d")], help: "Description") var description: String?
        @Flag(name: [.customLong("include-serial", withSingleDash: true)], help: "Include device serial number (default: false)") var includeSerialNumber = false

        mutating func run() throws {
            guard let secKey = loadSecureEnclaveKey(tag: options.key) else {
                print("Key \(String(data: options.key, encoding: .utf8) ?? "") not found")
                throw ExitCode.failure
            }

            let publicKey = SecKeyCopyPublicKey(secKey)

            var error: Unmanaged<CFError>?
            let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
            let publicKeyBits: Data = ixy! as Data

            let keyAlgorithm = KeyAlgorithm.ec(signatureType: .sha256)
            let csr = CertificateSigningRequest.init(commonName: commonName,
                                                     organizationName: organizationName,
                                                     organizationUnitName: organizationUnitName?.split(separator: ";", omittingEmptySubsequences: true).map(String.init),
                                                     countryName: countryName,
                                                     stateOrProvinceName: stateOrProvinceName,
                                                     localityName: localityName,
                                                     serialNumber: includeSerialNumber ? serialNumber : nil,
                                                     emailAddress: emailAddress?.split(separator: ";", omittingEmptySubsequences: true).map(String.init),
                                                     description: description,
                                                     keyAlgorithm: keyAlgorithm)

            csr.addKeyUsage([KeyUsage.digitalSignature, KeyUsage.keyAgreement])
            csr.addExtendedKeyUsage(ExtendedKeyUsage.clientAuth)

            if let emailAddress = emailAddress {
                for email in emailAddress.split(separator: ";", omittingEmptySubsequences: true).map(String.init) {
                    csr.addSubjectAlternativeName(SubjectAlternativeName.rfc822Name(String(email)))
                }
            }

            guard let pem = csr.buildCSRAndReturnString(publicKeyBits, privateKey: secKey, publicKey: publicKey) else {
                print("Could not generate certificate signing request")
                throw ExitCode.failure
            }
            print(pem)
        }
    }

    struct Pub: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Get the public key for a secure enclave backed key."
        )

        @OptionGroup var options: Options

        mutating func run() throws {
            guard let secKey = loadSecureEnclaveKey(tag: options.key) else {
                print("Key \(String(data: options.key, encoding: .utf8) ?? "") not found")
                throw ExitCode.failure
            }

            let publicKey = SecKeyCopyPublicKey(secKey)

            var error: Unmanaged<CFError>?
            let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
            let bytes: Data = ixy! as Data
            print(bytes.base64EncodedString())
        }
    }

    struct Keys: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "List known private keys stored in the secure enclave."
        )

        mutating func run() throws {
            var item: AnyObject?

            let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                                        kSecReturnRef as String: true,
                                        kSecReturnAttributes as String: true,
                                        kSecMatchLimit as String: kSecMatchLimitAll,
            ]

            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess else {
                print("Error querying secure enclave, \(status)")
                throw ExitCode.failure
            }

            // https://opensource.apple.com/source/Security/Security-59754.80.3/OSX/sec/Security/SecItemConstants.c.auto.html

            print("Public Key Hash                           Created                    Tag")
            for attr in item as! [NSDictionary] {
                let atag = attr[kSecAttrApplicationTag as String] as? Data
                let cdat = attr[kSecAttrCreationDate as String] as? Date
                let klbl = attr[kSecAttrApplicationLabel as String] as? Data
                print(String(format: "%@  %@  %@", klbl!.hexEncodedString(), cdat!.description, String(data: atag!, encoding: .utf8)!))
            }
        }
    }

    struct Token: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Manage secure enclave token configuration.",
            subcommands: [Info.self, List.self, Import.self, Remove.self, Clear.self],
            defaultSubcommand: Info.self
        )
    }

}

extension SecureEnclaveTokenCLI.Token {
    struct Info: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Display information about this token configuration."
        )

        mutating func run() throws {
            guard let tokenConfig = loadTokenConfig() else {
                print("Could not load token configuration.")
                throw ExitCode.failure
            }

            print("Token instance ID: \(tokenConfig.instanceID)")
            print("\(tokenConfig.keychainItems.count) items loaded.")
        }
    }

    struct List: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "List keys and certificates in the token configuration."
        )

        mutating func run() throws {
            guard let tokenConfig = loadTokenConfig() else {
                print("Could not load token configuration.")
                throw ExitCode.failure
            }

            let items = Dictionary(grouping: tokenConfig.keychainItems, by: {
                (element: TKTokenKeychainItem) in return element.objectID as! Data })

            for objectID in items.keys {
                let certificate = try? tokenConfig.certificate(for: objectID)
                let key = try? tokenConfig.key(for: objectID)
                var usage: [String] = []
                if let key = key {
                    if key.canSign {
                        usage.append("sign")
                    }
                    if key.canDecrypt {
                        usage.append("decrypt")
                    }
                    if key.canPerformKeyExchange {
                        usage.append("derive")
                    }

                    var keyType: String
                    switch key.keyType as CFString {
                    case kSecAttrKeyTypeRSA:
                        keyType = "RSA"
                    case kSecAttrKeyTypeECSECPrimeRandom:
                        keyType = "ECC"
                    default:
                        keyType = "ECC"
                    }

                    print("""
Private Key Object; \(keyType)
  label:    \(key.label ?? "")
  ID:       \(String(data: objectID, encoding: .utf8) ?? "")
  Usage:    \(usage.joined(separator: ", "))
Public Key Object; \(keyType) \(key.keySizeInBits) bits
  label:    \(key.label ?? "")
  ID:       \(String(data: objectID, encoding: .utf8) ?? "")
  keyHash:  \(key.publicKeyHash?.map { String(format: "%02hhx", $0) }.joined() ?? "")
  keyData:  \(key.publicKeyData?.base64EncodedString() ?? "")
""")
                }

                if let certificate = certificate {
                    let cert = SecCertificateCreateWithData(nil, certificate.data as CFData)!
                    let subject = SecCertificateCopySubjectSummary(cert) as? String
                    print("""
Certificate Object; type = X.509 cert
  label:    \(certificate.label ?? "")
  subject:  \(subject ?? "")
  ID:       \(String(data: objectID, encoding: .utf8) ?? "")
""")
                }
            }

        }
    }

    struct Import: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Map a certificate to a key in the token configuration."
        )

        @OptionGroup var options: Options
        @Argument(help: "The DER-encoded certificate", transform:({return URL(fileURLWithPath: $0)})) var cert: URL

        mutating func run() throws {
            guard let tokenConfig = loadTokenConfig() else {
                print("Could not load token configuration.")
                throw ExitCode.failure
            }

            do {
                try tokenConfig.certificate(for: options.key)
                print("A token is already loaded for this key, remove it before importing a new certificate.")
                throw ExitCode.failure
            } catch is TKError {
                // carry on
            }

            var derBytes: Data
            do {
                derBytes = try Data(contentsOf: cert)
            } catch {
                print("Error reading file, exiting.")
                throw ExitCode.failure
            }

            guard let certificate = SecCertificateCreateWithData(nil, derBytes as CFData) else {
                print("Error parsing certificate, exiting.")
                throw ExitCode.failure
            }

            do {
                try addCertificateToToken(certificate: certificate, tag: options.key, tokenConfig: tokenConfig)
                print("Successfully loaded certificate into token \(String(data: options.key, encoding: .utf8) ?? "")")
            } catch CertificateImportError.keysMismatch {
                print("Error laoding certificate into token, public key does not match.")
                throw ExitCode.failure
            } catch CertificateImportError.keyDoesNotExist {
                print("Error loading certificate into token, \(String(data: options.key, encoding: .utf8) ?? "") does not exist")
                throw ExitCode.failure
            } catch {
                print("Error loading certificate into token, exiting.")
                throw ExitCode.failure
            }

            return
        }
    }

    struct Remove: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Remove a mapped certificate and key from the token configuration."
        )

        @OptionGroup var options: Options

        mutating func run() throws {
            guard let tokenConfig = loadTokenConfig() else {
                print("Could not load token configuration.")
                throw ExitCode.failure
            }

            let foundItems = tokenConfig.keychainItems.filter({ $0.objectID as! Data == options.key })

            guard !foundItems.isEmpty else {
                print("Token not found with name \(String(data: options.key, encoding: .utf8) ?? "")")
                throw ExitCode.failure
            }

            tokenConfig.keychainItems = tokenConfig.keychainItems.filter({ $0.objectID as! Data != options.key })
        }
    }

    struct Clear: ParsableCommand {
        static var configuration = CommandConfiguration(
            abstract: "Clear keys and certificates from token configuration."
        )

        mutating func run() throws {
            guard let tokenConfig = loadTokenConfig() else {
                print("Could not load token configuration.")
                throw ExitCode.failure
            }

            guard !tokenConfig.keychainItems.isEmpty else {
                print("Token configuration is already empty.")
                throw ExitCode.failure
            }

            tokenConfig.keychainItems.removeAll()
            print("Cleared token configuration.")
        }
    }
}


var driverConfig: TKTokenDriver.Configuration {
    TKTokenDriver.Configuration.driverConfigurations["com.mwielgoszewski.SecureEnclaveToken.SecureEnclaveTokenExtension"]!
}

var serialNumber: String? {
    let platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice") )

    guard platformExpert > 0 else {
        return nil
    }

    let serialNumber = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0).takeUnretainedValue() as? String)

    IOObjectRelease(platformExpert)
    return serialNumber
}


// A unique, persistent identifier for this token.
// This value is typically generated from the serial number of the target hardware.
var tokenID: String {
    let fallbackInstanceID = "819D11D7A8F7D609F236F529996E9F4C"

    guard serialNumber != nil else {
        return fallbackInstanceID
    }

    let serialHash = SHA256.hash(data: serialNumber!.data(using: .utf8)!).hexStr.dropLast(32)
    return String(serialHash)
}


func loadTokenConfig() -> TKToken.Configuration? {
    if driverConfig.tokenConfigurations.isEmpty {
        driverConfig.addTokenConfiguration(for: tokenID)
    }
    var tokenConfig = driverConfig.tokenConfigurations[tokenID]
    if tokenConfig == nil {
        tokenConfig = driverConfig.addTokenConfiguration(for: tokenID)
    }
    return tokenConfig
}

func unloadTokenConfig() {
    driverConfig.removeTokenConfiguration(for: tokenID)
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
