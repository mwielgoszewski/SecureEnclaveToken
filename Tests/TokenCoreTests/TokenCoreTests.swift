import CryptoKit
import CryptoTokenKit
import Foundation
import Security
import Testing
import X509
@testable import TokenCore

struct TokenCoreTests {
    // Ephemeral software keys exercise formats and signatures without touching the user's keychain.
    private func makeKey(bits: Int = 256) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: bits
        ]
        var error: Unmanaged<CFError>?
        return try #require(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
    }

    @Test func csrPreservesSubjectAndVerifiesWithOpenSSL() throws {
        let key = try makeKey()
        let subject = CertificateSubject(
            commonName: "Renée Example", emailAddress: "one@example.com; two@example.com",
            organization: "Example Org", organizationalUnit: "Engineering; Security",
            locality: "New York", province: "New York", country: "us"
        )
        let data = try subject.signingRequest(for: key)
        let parsed = try CertificateSigningRequest(pemEncoded: String(decoding: data, as: UTF8.self))
        #expect(parsed.signatureAlgorithm == .ecdsaWithSHA256)
        #expect(parsed.publicKey.isValidSignature(parsed.signature, for: parsed))
        #expect(parsed.publicKey == (try Certificate.PrivateKey(key).publicKey))
        let expected = try DistinguishedName {
            CountryName("US")
            StateOrProvinceName("New York")
            LocalityName("New York")
            OrganizationName("Example Org")
            OrganizationalUnitName("Engineering")
            OrganizationalUnitName("Security")
            CommonName("Renée Example")
            EmailAddress("one@example.com")
            EmailAddress("two@example.com")
        }
        #expect(parsed.subject == expected)

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("test.csr")
        try data.write(to: url)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["req", "-in", url.path, "-verify", "-noout"]
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = pipe
        try process.run()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        #expect(process.terminationStatus == 0, "OpenSSL rejected the CSR: \(output)")
    }

    @Test func csrRejectsMissingNameAndInvalidCountry() throws {
        let key = try makeKey()
        for subject in [CertificateSubject(), CertificateSubject(commonName: "  "),
                        CertificateSubject(commonName: "Test", country: "USA"),
                        CertificateSubject(commonName: "Test", country: "12")] {
            #expect(!subject.isValid)
            #expect(throws: (any Error).self) { try subject.signingRequest(for: key) }
        }
        #expect(CertificateSubject(commonName: "Test").isValid)
    }

    @Test func publicKeyExportIsValidSubjectPublicKeyInfo() throws {
        let key = try makeKey()
        let publicKey = try TokenSecurity.publicKey(for: key)
        let der = try TokenSecurity.subjectPublicKeyInfo(publicKey)
        let decoded = try P256.Signing.PublicKey(derRepresentation: der)
        #expect(decoded.x963Representation == (try TokenSecurity.externalRepresentation(of: publicKey)))
        let wrongCurve = try TokenSecurity.publicKey(for: makeKey(bits: 384))
        #expect(throws: (any Error).self) { try TokenSecurity.subjectPublicKeyInfo(wrongCurve) }
    }

    @Test func certificateImportAcceptsPEMAndDERAndRejectsMismatchedKeys() throws {
        let key = try makeKey()
        let signingKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("Test identity") }
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: signingKey.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_700_000_000),
            notValidAfter: Date(timeIntervalSince1970: 2_000_000_000),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: .init(), issuerPrivateKey: signingKey
        )
        let pem = try certificate.serializeAsPEM()
        let publicKey = try TokenSecurity.publicKey(for: key)
        let otherPublicKey = try TokenSecurity.publicKey(for: makeKey())
        for data in [Data(pem.pemString.utf8), Data(pem.derBytes)] {
            let parsed = try TokenSecurity.certificate(from: data)
            try TokenSecurity.validate(parsed, matches: publicKey)
            #expect(throws: (any Error).self) { try TokenSecurity.validate(parsed, matches: otherPublicKey) }
        }
        #expect(throws: (any Error).self) {
            try TokenSecurity.certificate(from: Data((pem.pemString + "\n" + pem.pemString).utf8))
        }
    }

    @Test func invalidCertificatesFailWithoutCrashing() {
        for data in [Data(), Data("not a certificate".utf8),
                     Data("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----".utf8),
                     Data("-----BEGIN CERTIFICATE-----\nAAAA".utf8)] {
            #expect(throws: (any Error).self) { try TokenSecurity.certificate(from: data) }
        }
    }

    @Test func keyQueryPreservesBinaryTagAndPrivateKeyScope() {
        let query = TokenSecurity.keyQuery()
        #expect(query[kSecAttrApplicationTag as String] as? Data == TokenConstants.keyTag)
        #expect(query[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String)
        #expect(query[kSecClass as String] as? String == kSecClassKey as String)
        #expect(query[kSecReturnRef as String] == nil)
    }

    @Test func invalidTokenObjectIDsAreRejected() throws {
        try TokenAlgorithms.validateObjectID(TokenConstants.keyTag)
        #expect(try TokenAlgorithms.validateObjectID(Data("named-key".utf8)) == Data("named-key".utf8))
        for value: Any in ["com.mwielgoszewski.SecureEnclaveToken.Key", Data(), 42] {
            #expect(throws: (any Error).self) { try TokenAlgorithms.validateObjectID(value) }
        }
    }

    @Test func keyExchangeParametersProduceMatchingSecrets() throws {
        let alice = try makeKey()
        let bob = try makeKey()
        let parameters = TokenAlgorithms.exchangeParameters(requestedSize: 32, sharedInfo: Data("context".utf8))
        #expect(parameters[SecKeyKeyExchangeParameter.requestedSize.rawValue as String] as? Int == 32)
        #expect(TokenAlgorithms.exchangeParameters(requestedSize: 32, sharedInfo: nil)[SecKeyKeyExchangeParameter.sharedInfo.rawValue as String] == nil)
        var error: Unmanaged<CFError>?
        let aliceSecret = try #require(SecKeyCopyKeyExchangeResult(
            alice, .ecdhKeyExchangeStandardX963SHA256, TokenSecurity.publicKey(for: bob), parameters as CFDictionary, &error
        )) as Data
        let bobSecret = try #require(SecKeyCopyKeyExchangeResult(
            bob, .ecdhKeyExchangeStandardX963SHA256, TokenSecurity.publicKey(for: alice), parameters as CFDictionary, &error
        )) as Data
        #expect(aliceSecret.count == 32)
        #expect(aliceSecret == bobSecret)
    }

    @Test func softwareKeysAreRecognizedAsSoftware() throws {
        #expect(try !TokenSecurity.isHardwareBacked(makeKey()))
    }
}
