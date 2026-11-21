import ArgumentParser
import CryptoTokenKit
import Foundation
import Security

struct SecureEnclaveTokenCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setoken",
        abstract: "Manage Secure Enclave keys, certificates and persistent token identities.",
        subcommands: [New.self, Destroy.self, Req.self, SelfSign.self, Pub.self, Keys.self, Token.self]
    )
}

struct KeyArguments: ParsableArguments {
    @Argument(help: "The private key's application tag.") var key: String
    var tag: Data { Data(key.utf8) }
    func validate() throws {
        guard !key.isEmpty else { throw ValidationError("The key tag must not be empty.") }
    }
}

struct SubjectArguments: ParsableArguments {
    @Option(name: [.customLong("cn", withSingleDash: true)], help: "Common name.") var commonName = ""
    @Option(name: .customShort("o")) var organizationName = ""
    @Option(name: .customLong("ou", withSingleDash: true)) var organizationUnitName = ""
    @Option(name: .customShort("c")) var countryName = ""
    @Option(name: .customLong("st", withSingleDash: true)) var stateOrProvinceName = ""
    @Option(name: .customShort("l")) var localityName = ""
    @Option(name: .customLong("email", withSingleDash: true)) var emailAddress = ""
    @Option(name: .customShort("d")) var description = ""
    @Flag(name: .customLong("include-serial", withSingleDash: true)) var includeSerialNumber = false
    @Option(help: "Repeatable subject attribute: OID=Unicode text.") var subjectAttribute: [String] = []
    @Option(help: "Repeatable subject attribute: OID=DER hexadecimal value.") var subjectDer: [String] = []

    func subject() throws -> CertificateSubject {
        var subject = CertificateSubject(commonName: commonName, emailAddress: emailAddress,
            organization: organizationName, organizationalUnit: organizationUnitName,
            locality: localityName, province: stateOrProvinceName, country: countryName,
            description: description, serialNumber: includeSerialNumber ? (TokenRegistry.serialNumber ?? "") : "")
        for (specs, encoding) in [(subjectAttribute, CustomSubjectAttribute.Encoding.utf8), (subjectDer, .der)] {
            for spec in specs {
                let (oid, value) = try splitAssignment(spec)
                subject.customAttributes.append(.init(oid: oid, encoding: encoding, value: value))
            }
        }
        _ = try subject.distinguishedName()
        return subject
    }
}

struct ExtensionArguments: ParsableArguments {
    @Option(help: "Repeatable SAN: DNS:name, email:address, URI:uri, or IP:address.") var san: [String] = []
    @Option(help: "Repeatable extended key usage OID. Defaults to client authentication.") var eku: [String] = []
    @Flag(help: "Omit the default extended key usage extension.") var noEku = false
    @Flag(help: "Omit the default digital-signature and key-agreement usage extension.") var noKeyUsage = false
    @Flag(help: "Do not automatically add subject email addresses as SANs.") var noEmailSan = false
    @Option(name: .customLong("extension"), help: "Repeatable extension: OID=DERHEX or OID:critical=DERHEX. Value excludes the outer OCTET STRING.") var extensions: [String] = []

    func options(emailAddresses: String) throws -> CertificateOptions {
        if noEku && !eku.isEmpty { throw ValidationError("Use --eku or --no-eku, not both.") }
        var options = CertificateOptions()
        options.digitalSignature = !noKeyUsage
        options.keyAgreement = !noKeyUsage
        options.extendedKeyUsage = noEku ? "" : (eku.isEmpty ? options.extendedKeyUsage : eku.joined(separator: "\n"))
        var names = san
        if !noEmailSan {
            names += emailAddresses.split(separator: ";").map { "email:" + $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        }
        options.subjectAlternativeNames = names.joined(separator: "\n")
        for specification in extensions {
            let (identifier, value) = try splitAssignment(specification)
            let critical = identifier.hasSuffix(":critical")
            let oid = critical ? String(identifier.dropLast(9)) : identifier
            options.customExtensions.append(.init(oid: oid, critical: critical, valueHex: value))
        }
        _ = try options.extensions()
        return options
    }
}

private func splitAssignment(_ input: String) throws -> (String, String) {
    guard let delimiter = input.firstIndex(of: "="), delimiter != input.startIndex else {
        throw ValidationError("Expected OID=value: \(input)")
    }
    return (String(input[..<delimiter]), String(input[input.index(after: delimiter)...]))
}

extension SecureEnclaveTokenCLI {
    struct New: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Generate a Secure Enclave key.")
        enum Require: String, ExpressibleByArgument { case none, userPresence, biometryAny, biometryCurrentSet, devicePasscode }
        enum Availability: String, ExpressibleByArgument { case whenUnlocked, afterFirstUnlock }
        @OptionGroup var options: KeyArguments
        // Preserve the existing CLI defaults; the UI defaults to user presence / when unlocked.
        @Option var require: Require = .none
        @Option var available: Availability = .afterFirstUnlock
        mutating func run() throws {
            let authentication: KeyAuthentication
            switch require {
            case .none: authentication = .none
            case .userPresence: authentication = .userPresence
            case .biometryAny: authentication = .biometrics
            case .biometryCurrentSet: authentication = .biometryCurrentSet
            case .devicePasscode: authentication = .devicePasscode
            }
            try TokenSecurity.generateKey(tag: options.tag,
                accessibility: available == .whenUnlocked ? .whenUnlocked : .afterFirstUnlock,
                authentication: authentication)
            print("Created key \(options.key).")
        }
    }
    struct Destroy: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Permanently delete a key and unload only its identity.")
        @OptionGroup var options: KeyArguments
        mutating func run() throws {
            guard try TokenSecurity.loadKey(tag: options.tag) != nil else { throw ValidationError("Key not found: \(options.key)") }
            try TokenRegistry.remove(tag: options.tag)
            try TokenSecurity.deleteKey(tag: options.tag)
            print("Deleted key \(options.key).")
        }
    }
    struct Req: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Write a PEM certificate signing request to stdout.")
        @OptionGroup var options: KeyArguments
        @OptionGroup var subjectOptions: SubjectArguments
        @OptionGroup var extensionOptions: ExtensionArguments
        mutating func validate() throws {
            _ = try subjectOptions.subject()
            _ = try extensionOptions.options(emailAddresses: subjectOptions.emailAddress)
        }
        mutating func run() throws {
            let subject = try subjectOptions.subject()
            let extensions = try extensionOptions.options(emailAddresses: subjectOptions.emailAddress)
            let data = try subject.signingRequest(for: TokenSecurity.requireKey(tag: options.tag), options: extensions)
            try FileHandle.standardOutput.write(contentsOf: data)
        }
    }
    struct SelfSign: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "self-sign", abstract: "Create and load a self-signed identity; write its PEM certificate to stdout. Does not change trust settings.")
        @OptionGroup var options: KeyArguments
        @OptionGroup var subjectOptions: SubjectArguments
        @OptionGroup var extensionOptions: ExtensionArguments
        @Option(help: "Validity in days; must be positive.") var days: Int = 365
        @Option(help: "Optional positive serial number in hexadecimal; otherwise random.") var serial = ""
        @Option(help: "Start time in ISO 8601, e.g. 2026-11-21T12:00:00Z.") var notBefore: String?
        @Option(help: "End time in ISO 8601. Overrides --days.") var notAfter: String?
        @Flag(inversion: .prefixedNo, help: "Publish this identity, replacing this key's existing certificate. Use --no-load for PEM-only output.") var load = true
        func validity() throws -> SelfSignedOptions {
            guard days > 0, days <= 36500 else { throw ValidationError("--days must be between 1 and 36500.") }
            func date(_ text: String) throws -> Date {
                guard let value = ISO8601DateFormatter().date(from: text) else { throw ValidationError("Invalid ISO 8601 date: \(text)") }
                return value
            }
            let start = try notBefore.map(date) ?? Date().addingTimeInterval(-300)
            let end = try notAfter.map(date) ?? start.addingTimeInterval(Double(days) * 86400)
            let result = SelfSignedOptions(notBefore: start, notAfter: end, serialHex: serial)
            _ = try result.serialNumber()
            return result
        }
        mutating func validate() throws {
            _ = try subjectOptions.subject()
            _ = try extensionOptions.options(emailAddresses: subjectOptions.emailAddress).extensions(selfSigned: true)
            _ = try validity()
        }
        mutating func run() throws {
            let subject = try subjectOptions.subject()
            let extensions = try extensionOptions.options(emailAddresses: subjectOptions.emailAddress)
            let data = try subject.selfSignedCertificate(for: TokenSecurity.requireKey(tag: options.tag), options: extensions, validity: validity())
            if load { try TokenRegistry.install(certificateData: data, tag: options.tag) }
            try FileHandle.standardOutput.write(contentsOf: data)
        }
    }
    struct Pub: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the base64 X9.63 public key (legacy format), or DER SPKI with --der.")
        @OptionGroup var options: KeyArguments
        @Flag(help: "Write binary DER SubjectPublicKeyInfo to stdout.") var der = false
        mutating func run() throws {
            let key = try TokenSecurity.publicKey(for: TokenSecurity.requireKey(tag: options.tag))
            if der { try FileHandle.standardOutput.write(contentsOf: TokenSecurity.subjectPublicKeyInfo(key)) }
            else { print(try TokenSecurity.externalRepresentation(of: key).base64EncodedString()) }
        }
    }
    struct Keys: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List accessible Secure Enclave private keys.")
        mutating func run() throws {
            var item: CFTypeRef?
            let query: [String: Any] = [kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            if status == errSecItemNotFound { print("No keys found."); return }
            guard status == errSecSuccess else { throw TokenFailure.security(status) }
            guard let items = item as? [[String: Any]] else { throw TokenFailure.message("Unexpected keychain result.") }
            print("Public Key Hash                           Created                    Tag")
            for attributes in items {
                let tag = attributes[kSecAttrApplicationTag as String] as? Data ?? Data()
                let hash = attributes[kSecAttrApplicationLabel as String] as? Data ?? Data()
                let date = attributes[kSecAttrCreationDate as String] as? Date
                print("\(hash.map { String(format: "%02x", $0) }.joined())  \(date?.description ?? "unknown")  \(String(decoding: tag, as: UTF8.self))")
            }
        }
    }
    struct Token: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Manage the persistent token.",
            subcommands: [Info.self, List.self, Import.self, Remove.self, Clear.self], defaultSubcommand: Info.self)
        struct Info: ParsableCommand {
            mutating func run() throws {
                let config = try TokenRegistry.configuration()
                print("Token instance ID: \(TokenRegistry.instanceID)")
                print("\(config?.keychainItems.count ?? 0) items loaded.")
            }
        }
        struct List: ParsableCommand {
            mutating func run() throws {
                let items = try TokenRegistry.configuration()?.keychainItems ?? []
                for item in items {
                    let tag = item.objectID as? Data ?? Data()
                    print("\(item is TKTokenKeychainKey ? "Private Key" : "Certificate") Object")
                    print("  label: \(item.label ?? "")\n  ID: \(String(decoding: tag, as: UTF8.self))")
                    if let key = item as? TKTokenKeychainKey {
                        print("  Usage: \([key.canSign ? "sign" : nil, key.canPerformKeyExchange ? "derive" : nil].compactMap { $0 }.joined(separator: ", "))")
                        print("  keyData: \(key.publicKeyData?.base64EncodedString() ?? "")")
                    }
                }
            }
        }
        struct Import: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Import a matching DER/PEM certificate. Use - to read stdin.")
            @OptionGroup var options: KeyArguments
            @Argument var cert: String
            @Flag var replace = false
            mutating func run() throws {
                let data = try cert == "-" ? FileHandle.standardInput.readToEnd() ?? Data() : Data(contentsOf: URL(fileURLWithPath: cert))
                try TokenRegistry.install(certificateData: data, tag: options.tag, replace: replace)
                print("Loaded certificate for \(options.key).")
            }
        }
        struct Remove: ParsableCommand {
            @OptionGroup var options: KeyArguments
            mutating func run() throws { try TokenRegistry.remove(tag: options.tag) }
        }
        struct Clear: ParsableCommand {
            mutating func run() throws { try TokenRegistry.clear(); print("Cleared token configuration.") }
        }
    }
}
