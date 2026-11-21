import ArgumentParser
import CryptoTokenKit
import Foundation
import Security
import SwiftASN1
import Testing
import X509
@testable import TokenCore

struct CertificateOptionsTests {
    private func key() throws -> SecKey {
        var error: Unmanaged<CFError>?
        return try #require(SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ] as CFDictionary, &error))
    }

    @Test func customExtensionsAndSubjectSurviveCSRAndCertificate() throws {
        let key = try key()
        let customOID = try CertificateOptions.oid("1.3.6.1.4.1.55555.1")
        let custom = CustomCertificateExtension(oid: "1.3.6.1.4.1.55555.1", critical: false, valueHex: "0C 05 68 65 6C 6C 6F")
        let options = CertificateOptions(subjectAlternativeNames: "DNS:example.com\nemail:test@example.com\nURI:https://example.com\nIP:192.0.2.1\nIP:2001:db8::1", customExtensions: [custom])
        let subject = CertificateSubject(commonName: "Custom identity", customAttributes: [
            .init(oid: "2.5.4.5", encoding: .printable, value: "12345"),
            .init(oid: "1.3.6.1.4.1.55555.2", encoding: .der, value: "0c0568656c6c6f")
        ])
        let request = try subject.signingRequest(for: key, options: options)
        let csr = try CertificateSigningRequest(pemEncoded: String(decoding: request, as: UTF8.self))
        let requestExtensions = try ExtensionRequest(#require(csr.attributes[oid: .CSRAttributes.extensionRequest])).extensions
        #expect(csr.publicKey.isValidSignature(csr.signature, for: csr))
        #expect(csr.subject == (try subject.distinguishedName()))
        #expect(Array(try #require(requestExtensions[oid: customOID]).value) == [0x0c, 5, 104, 101, 108, 108, 111])
        let names = try SubjectAlternativeNames(#require(requestExtensions[oid: .X509ExtensionID.subjectAlternativeName]))
        #expect(names.count == 5)

        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let end = Date(timeIntervalSince1970: 2_000_000_000)
        let pem = try subject.selfSignedCertificate(for: key, options: options,
            validity: .init(notBefore: start, notAfter: end, serialHex: "1234"))
        let certificate = try Certificate(pemEncoded: String(decoding: pem, as: UTF8.self))
        #expect(certificate.subject == csr.subject)
        #expect(certificate.issuer == certificate.subject)
        #expect(certificate.publicKey == csr.publicKey)
        #expect(certificate.publicKey.isValidSignature(certificate.signature, for: certificate))
        #expect(certificate.notValidBefore == start && certificate.notValidAfter == end)
        #expect(Array(certificate.serialNumber.bytes) == [0x12, 0x34])
        #expect(certificate.extensions[oid: customOID] == requestExtensions[oid: customOID])
        #expect(try BasicConstraints(#require(certificate.extensions[oid: .X509ExtensionID.basicConstraints])) == .notCertificateAuthority)
        let secCertificate = try TokenSecurity.certificate(from: pem)
        try TokenSecurity.validate(secCertificate, matches: TokenSecurity.publicKey(for: key))

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("self-signed.pem")
        try pem.write(to: url)
        let publicURL = directory.appendingPathComponent("public.der")
        let signatureURL = directory.appendingPathComponent("signature.der")
        let bodyURL = directory.appendingPathComponent("body.der")
        try TokenSecurity.subjectPublicKeyInfo(TokenSecurity.publicKey(for: key)).write(to: publicURL)
        let der = try certificate.serializeAsPEM().derBytes
        guard case .constructed(let children) = try DER.parse(der).content else {
            Issue.record("Expected certificate sequence"); return
        }
        let signature = try ASN1BitString(derEncoded: #require(Array(children).last))
        try Data(signature.bytes).write(to: signatureURL)
        try Data(certificate.tbsCertificateBytes).write(to: bodyURL)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["dgst", "-sha256", "-verify", publicURL.path, "-keyform", "DER", "-signature", signatureURL.path, bodyURL.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "OpenSSL verification failed: \(output)")
    }

    @Test func criticalCustomExtensionAndPresetOverride() throws {
        let custom = CustomCertificateExtension(oid: "2.5.29.19", critical: true, valueHex: "30030101ff")
        let options = CertificateOptions(customExtensions: [custom])
        let extensions = try options.extensions(selfSigned: true)
        let ext = try #require(extensions[oid: .X509ExtensionID.basicConstraints])
        #expect(ext.critical)
        #expect(Array(ext.value) == [0x30, 3, 1, 1, 255])
        #expect(extensions.filter { $0.oid == .X509ExtensionID.basicConstraints }.count == 1)
    }

    @Test func malformedOIDsDERAndDuplicateExtensionsAreRejected() {
        for oid in ["", "1", "3.1.2", "1.40.1", "1..2", "1.-2.3", "1.2.no", "1.2.99999999999999999999999999", "2.18446744073709551615"] {
            #expect(throws: (any Error).self) { try CertificateOptions.oid(oid) }
        }
        for hex in ["", "0", "gg", "050000", "0c056865", "048001020000"] {
            #expect(throws: (any Error).self) { try CertificateOptions.derBytes(hex) }
        }
        let duplicate = CertificateOptions(customExtensions: [.init(oid: "2.5.29.15", valueHex: "03020780")])
        #expect(throws: (any Error).self) { try duplicate.extensions() }
        let unknown = CustomCertificateExtension(oid: "1.2.3.4", valueHex: "0500")
        #expect(throws: (any Error).self) { try CertificateOptions(customExtensions: [unknown, unknown]).extensions() }
        #expect(throws: (any Error).self) { try CertificateOptions(subjectAlternativeNames: "IP:not-an-address").extensions() }
    }

    @Test func invalidValidityAndSerialAreRejected() {
        let now = Date()
        #expect(throws: (any Error).self) { try SelfSignedOptions(notBefore: now, notAfter: now).serialNumber() }
        for serial in ["00", "ff", String(repeating: "01", count: 21), "xyz"] {
            #expect(throws: (any Error).self) { try SelfSignedOptions(serialHex: serial).serialNumber() }
        }
    }

    @Test func namedIdentityRemovalPreservesOtherKeys() {
        let first = Data("first".utf8), second = Data("second".utf8)
        let items = [TKTokenKeychainItem(objectID: first), TKTokenKeychainItem(objectID: second), TKTokenKeychainItem(objectID: first)]
        let retained = TokenRegistry.excluding(tag: first, from: items)
        #expect(retained.count == 1)
        #expect(retained.first?.objectID as? Data == second)
        #expect(TokenSecurity.keyQuery(tag: second)[kSecAttrApplicationTag as String] as? Data == second)
    }

    @Test func legacyCLIAndNewCertificateOptionsParse() throws {
        let new = try #require(SecureEnclaveTokenCLI.parseAsRoot(["new", "named-key", "--require", "biometryCurrentSet", "--available", "whenUnlocked"]) as? SecureEnclaveTokenCLI.New)
        #expect(new.options.key == "named-key")
        #expect(new.require == .biometryCurrentSet)
        let request = try #require(SecureEnclaveTokenCLI.parseAsRoot([
            "req", "named-key", "-cn", "Test", "-o", "Example", "-email", "one@example.com;two@example.com",
            "--san", "DNS:example.com", "--extension", "1.2.3.4:critical=0500", "--subject-attribute", "2.5.4.5=123"
        ]) as? SecureEnclaveTokenCLI.Req)
        #expect(try request.subjectOptions.subject().customAttributes.count == 1)
        let extensions = try request.extensionOptions.options(emailAddresses: request.subjectOptions.emailAddress).extensions()
        #expect(extensions[oid: try CertificateOptions.oid("1.2.3.4")]?.critical == true)
        #expect(try SubjectAlternativeNames(#require(extensions[oid: .X509ExtensionID.subjectAlternativeName])).count == 3)
        #expect(try SecureEnclaveTokenCLI.parseAsRoot(["self-sign", "named-key", "-cn", "Test", "--days", "30", "--serial", "1234"]) is SecureEnclaveTokenCLI.SelfSign)
        #expect(try SecureEnclaveTokenCLI.parseAsRoot(["pub", "named-key"]) is SecureEnclaveTokenCLI.Pub)
        #expect(try SecureEnclaveTokenCLI.parseAsRoot(["token", "import", "named-key", "-"]) is SecureEnclaveTokenCLI.Token.Import)
        #expect(try SecureEnclaveTokenCLI.parseAsRoot(["token"]) is SecureEnclaveTokenCLI.Token.Info)
    }

    @Test func standardAndCustomExtendedUsagesAreEncodedTogether() throws {
        var options = CertificateOptions()
        options.extendedKeyUsage = StandardExtendedKeyUsage.allCases.map(\.rawValue).joined(separator: "\n")
        options.customExtendedKeyUsages = [.init(oid: "1.3.6.1.4.1.55555.1")]
        let extensions = try options.extensions()
        let usage = try ExtendedKeyUsage(#require(extensions[oid: .X509ExtensionID.extendedKeyUsage]))
        #expect(usage.count == 7)
        #expect(usage.contains(try .init(oid: CertificateOptions.oid("1.3.6.1.4.1.55555.1"))))
        options.customExtendedKeyUsages.append(.init(oid: StandardExtendedKeyUsage.clientAuthentication.rawValue))
        #expect(throws: (any Error).self) { try options.extensions() }
        options.extendedKeyUsage = ""
        options.customExtendedKeyUsages = []
        #expect(try options.extensions()[oid: .X509ExtensionID.extendedKeyUsage] == nil)
        options.customExtendedKeyUsages = [.init(oid: "")]
        #expect(throws: (any Error).self) { try options.extensions() }
    }

    @Test func keyInventoryPreservesTagsAndExcludesTokenAliases() {
        let first = Data("Work VPN".utf8), binary = Data([0xff, 0x00, 0x42])
        let keys = TokenSecurity.storedKeys(from: [
            [kSecAttrApplicationTag as String: first, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave],
            [kSecAttrApplicationTag as String: first, kSecAttrTokenID as String: "our-published-token"],
            [kSecAttrApplicationTag as String: binary],
            [kSecAttrApplicationTag as String: Data()],
            [kSecAttrApplicationTag as String: "wrong-type"],
            [kSecAttrApplicationTag as String: Data("Other token".utf8), kSecAttrTokenID as String: "other-token"]
        ])
        #expect(keys.count == 2)
        #expect(keys.first(where: { $0.id == first })?.hardwareBacked == true)
        #expect(keys.first(where: { $0.id == binary })?.hardwareBacked == false)
        #expect(keys.first(where: { $0.id == binary })?.name == "ff0042")
    }

    @Test func subjectValidationIdentifiesTheFieldAndNormalizesCountry() throws {
        var subject = CertificateSubject()
        #expect(subject.commonNameValidationError != nil)
        #expect(subject.countryValidationError == nil)
        subject.commonName = "Test identity"
        #expect(subject.isValid)
        subject.country = "United States"
        #expect(subject.commonNameValidationError == nil)
        #expect(subject.countryValidationError != nil)
        subject.country = " us "
        #expect(subject.isValid)
        #expect(try subject.distinguishedName() == CertificateSubject(commonName: "Test identity", country: "US").distinguishedName())
        subject.country = "   "
        #expect(try subject.distinguishedName() == CertificateSubject(commonName: "Test identity").distinguishedName())
    }

    @Test func selfSigningLoadsTheIdentityUnlessExplicitlyDisabled() throws {
        let arguments = ["self-sign", "example", "-cn", "Example"]
        let defaultCommand = try #require(SecureEnclaveTokenCLI.parseAsRoot(arguments) as? SecureEnclaveTokenCLI.SelfSign)
        #expect(defaultCommand.load)
        let exportOnly = try #require(SecureEnclaveTokenCLI.parseAsRoot(arguments + ["--no-load"]) as? SecureEnclaveTokenCLI.SelfSign)
        #expect(!exportOnly.load)
        let legacyFlag = try #require(SecureEnclaveTokenCLI.parseAsRoot(arguments + ["--load"]) as? SecureEnclaveTokenCLI.SelfSign)
        #expect(legacyFlag.load)
    }

    @Test func badCLIInputFailsBeforeKeyOperations() {
        for arguments in [["req", "key", "-cn", "Test", "--extension", "1.2.3=bad"],
                          ["self-sign", "key", "-cn", "Test", "--days", "0"],
                          ["self-sign", "key", "-cn", "Test", "--not-after", "yesterday"],
                          ["req", "key", "-cn", "Test", "--eku", "1.2.3", "--no-eku"],
                          ["new", ""]] {
            #expect(throws: (any Error).self) { try SecureEnclaveTokenCLI.parseAsRoot(arguments) }
        }
    }
}
