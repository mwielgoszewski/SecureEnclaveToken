import Foundation
import Security
import SwiftASN1
import X509

struct CertificateSubject: Sendable {
    var commonName = ""
    var emailAddress = ""
    var organization = ""
    var organizationalUnit = ""
    var locality = ""
    var province = ""
    var country = ""
    var description = ""
    var serialNumber = ""
    var customAttributes: [CustomSubjectAttribute] = []

    var commonNameValidationError: String? {
        commonName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "Enter a common name in Subject, such as your name or a hostname." : nil
    }

    var countryValidationError: String? {
        let value = country.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty || (value.utf8.count == 2 && value.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) })
            ? nil : "Country must be a two-letter code, such as US. You can also leave it blank."
    }

    var isValid: Bool { commonNameValidationError == nil && countryValidationError == nil }

    func distinguishedName() throws -> DistinguishedName {
        if let error = commonNameValidationError ?? countryValidationError {
            throw TokenFailure.message(error)
        }
        func trimmed(_ value: String) -> String { value.trimmingCharacters(in: .whitespacesAndNewlines) }
        func values(_ value: String) -> [String] {
            value.split(separator: ";").map { trimmed(String($0)) }.filter { !$0.isEmpty }
        }
        let name = try DistinguishedName {
            if !trimmed(country).isEmpty { CountryName(trimmed(country).uppercased()) }
            if !trimmed(province).isEmpty { StateOrProvinceName(trimmed(province)) }
            if !trimmed(locality).isEmpty { LocalityName(trimmed(locality)) }
            if !trimmed(organization).isEmpty { OrganizationName(trimmed(organization)) }
            for unit in values(organizationalUnit) { OrganizationalUnitName(unit) }
            CommonName(trimmed(commonName))
            for email in values(emailAddress) { EmailAddress(email) }
        }
        var attributes = customAttributes
        if !description.isEmpty { attributes.append(.init(oid: "2.5.4.13", value: description)) }
        if !serialNumber.isEmpty { attributes.append(.init(oid: "2.5.4.5", encoding: .printable, value: serialNumber)) }
        let additional = try attributes.map { RelativeDistinguishedName(try $0.attribute()) }
        return DistinguishedName(Array(name) + additional)
    }

    func signingRequest(for privateKey: SecKey, options: CertificateOptions = .init()) throws -> Data {
        let name = try distinguishedName()
        let extensions = try options.extensions()
        let attributes = try CertificateSigningRequest.Attributes([.init(ExtensionRequest(extensions: extensions))])
        // Security.framework signs using the existing key; private bytes stay in the enclave.
        let request = try CertificateSigningRequest(
            version: .v1, subject: name, privateKey: Certificate.PrivateKey(privateKey),
            attributes: attributes, signatureAlgorithm: .ecdsaWithSHA256
        )
        return Data(try request.serializeAsPEM().pemString.utf8)
    }

    func selfSignedCertificate(for privateKey: SecKey, options: CertificateOptions = .init(),
                               validity: SelfSignedOptions = .init()) throws -> Data {
        let name = try distinguishedName()
        let serial = try validity.serialNumber()
        let extensions = try options.extensions(selfSigned: true)
        let key = try Certificate.PrivateKey(privateKey)
        let certificate = try Certificate(
            version: .v3, serialNumber: serial, publicKey: key.publicKey,
            notValidBefore: validity.notBefore, notValidAfter: validity.notAfter,
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions, issuerPrivateKey: key
        )
        return Data(try certificate.serializeAsPEM().pemString.utf8)
    }
}
