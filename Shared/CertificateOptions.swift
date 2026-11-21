import Darwin
import Foundation
import SwiftASN1
import X509

struct CustomSubjectAttribute: Identifiable, Sendable {
    enum Encoding: String, CaseIterable, Identifiable, Sendable {
        case utf8 = "UTF-8", printable = "Printable", ia5 = "IA5", der = "DER hex"
        var id: Self { self }
    }
    let id = UUID()
    var oid = ""
    var encoding = Encoding.utf8
    var value = ""

    func attribute() throws -> RelativeDistinguishedName.Attribute {
        let identifier = try CertificateOptions.oid(oid)
        switch encoding {
        case .utf8: return .init(type: identifier, utf8String: value)
        case .printable: return try .init(type: identifier, printableString: value)
        case .ia5: return try .init(type: identifier, ia5String: value)
        case .der: return try .init(type: identifier, value: ASN1Any(derEncoded: DER.parse(CertificateOptions.derBytes(value))))
        }
    }
}

struct CustomCertificateExtension: Identifiable, Sendable {
    let id = UUID()
    var oid = ""
    var critical = false
    var valueHex = ""

    func certificateExtension() throws -> Certificate.Extension {
        try .init(oid: CertificateOptions.oid(oid), critical: critical, value: CertificateOptions.derBytes(valueHex)[...])
    }
}

// RFC 5280 §4.2.1.12: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12
enum StandardExtendedKeyUsage: String, CaseIterable, Identifiable, Sendable {
    case clientAuthentication = "1.3.6.1.5.5.7.3.2"
    case serverAuthentication = "1.3.6.1.5.5.7.3.1"
    case codeSigning = "1.3.6.1.5.5.7.3.3"
    case emailProtection = "1.3.6.1.5.5.7.3.4"
    case timeStamping = "1.3.6.1.5.5.7.3.8"
    case ocspSigning = "1.3.6.1.5.5.7.3.9"
    var id: String { rawValue }
    var title: String {
        switch self {
        case .clientAuthentication: "Client authentication"
        case .serverAuthentication: "Server authentication"
        case .codeSigning: "Code signing"
        case .emailProtection: "Email protection"
        case .timeStamping: "Time stamping"
        case .ocspSigning: "OCSP signing"
        }
    }
}

struct CustomExtendedKeyUsage: Identifiable, Sendable {
    let id = UUID()
    var oid = ""
}

struct CertificateOptions: Sendable {
    var digitalSignature = true
    var keyAgreement = true
    var extendedKeyUsage = "1.3.6.1.5.5.7.3.2"
    var customExtendedKeyUsages: [CustomExtendedKeyUsage] = []
    var subjectAlternativeNames = ""
    var customExtensions: [CustomCertificateExtension] = []

    static func oid(_ text: String) throws -> ASN1ObjectIdentifier {
        // Avoid the library's string-literal initializer, which traps on malformed input.
        guard !text.isEmpty, text == text.trimmingCharacters(in: .whitespacesAndNewlines),
              text.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy { (48...57).contains($0) } }) else {
            throw TokenFailure.message("Invalid object identifier: \(text). Use dotted decimal notation.")
        }
        let parts = text.split(separator: ".").compactMap { UInt($0) }
        guard parts.count == text.split(separator: ".").count, parts.count >= 2,
              parts[0] <= 2, (parts[0] == 2 || parts[1] < 40),
              parts[1] <= UInt.max - parts[0] * 40 else {
            throw TokenFailure.message("Invalid object identifier: \(text).")
        }
        do { return try ASN1ObjectIdentifier(elements: parts) }
        catch { throw TokenFailure.message("Invalid object identifier: \(text).") }
    }

    static func hexBytes(_ text: String) throws -> [UInt8] {
        let hex = text.filter { !$0.isWhitespace && $0 != ":" }
        guard !hex.isEmpty, hex.utf8.count.isMultiple(of: 2), hex.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            throw TokenFailure.message("Enter complete hexadecimal bytes, optionally separated by spaces or colons.")
        }
        let characters = Array(hex)
        return try stride(from: 0, to: characters.count, by: 2).map {
            guard let byte = UInt8(String(characters[$0...($0 + 1)]), radix: 16) else { throw TokenFailure.message("Invalid hexadecimal value.") }
            return byte
        }
    }

    static func derBytes(_ text: String) throws -> [UInt8] {
        let bytes = try hexBytes(text)
        do { _ = try DER.parse(bytes) }
        catch { throw TokenFailure.message("The value must contain exactly one complete DER-encoded ASN.1 value.") }
        return bytes
    }

    func extensions(selfSigned: Bool = false) throws -> Certificate.Extensions {
        var result = Certificate.Extensions()
        if digitalSignature || keyAgreement {
            try result.append(Certificate.Extension(KeyUsage(digitalSignature: digitalSignature, keyAgreement: keyAgreement), critical: true))
        }
        let usages = extendedKeyUsage.split(whereSeparator: { $0.isWhitespace || $0 == "," || $0 == ";" }).map(String.init) + customExtendedKeyUsages.map(\.oid)
        if !usages.isEmpty {
            let identifiers = try usages.map(Self.oid)
            guard Set(identifiers).count == identifiers.count else {
                throw TokenFailure.message("Duplicate extended key usage OID. Remove the duplicate or uncheck its standard usage.")
            }
            let eku = try ExtendedKeyUsage(identifiers.map { .init(oid: $0) })
            try result.append(Certificate.Extension(eku, critical: false))
        }
        let names = try subjectAlternativeNames.split(separator: "\n").map { try Self.generalName(String($0)) }
        if !names.isEmpty { try result.append(Certificate.Extension(SubjectAlternativeNames(names), critical: false)) }
        for item in customExtensions {
            let ext = try item.certificateExtension()
            guard result[oid: ext.oid] == nil else {
                throw TokenFailure.message("Duplicate extension OID \(item.oid). Disable its preset or remove the duplicate.")
            }
            try result.append(ext)
        }
        if selfSigned && result[oid: .X509ExtensionID.basicConstraints] == nil {
            try result.append(Certificate.Extension(BasicConstraints.notCertificateAuthority, critical: true))
        }
        return result
    }

    private static func generalName(_ input: String) throws -> GeneralName {
        let parts = input.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { throw TokenFailure.message("Use DNS:, email:, URI: or IP: before each subject alternative name.") }
        let text = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.allSatisfy({ $0 > 32 && $0 < 127 }) else { throw TokenFailure.message("Subject alternative names must be nonempty ASCII values. Use punycode for international domains.") }
        switch parts[0].lowercased() {
        case "dns": return .dnsName(text)
        case "email": return .rfc822Name(text)
        case "uri": return .uniformResourceIdentifier(text)
        case "ip":
            var ipv4 = in_addr()
            if inet_pton(AF_INET, text, &ipv4) == 1 { return .ipAddress(withUnsafeBytes(of: ipv4) { ASN1OctetString(contentBytes: Array($0)[...]) }) }
            var ipv6 = in6_addr()
            if inet_pton(AF_INET6, text, &ipv6) == 1 { return .ipAddress(withUnsafeBytes(of: ipv6) { ASN1OctetString(contentBytes: Array($0)[...]) }) }
            throw TokenFailure.message("Invalid IP address: \(text).")
        default: throw TokenFailure.message("Unknown subject alternative name type: \(parts[0]).")
        }
    }
}

struct SelfSignedOptions: Sendable {
    var notBefore = Date().addingTimeInterval(-300)
    var notAfter = Date().addingTimeInterval(365 * 24 * 60 * 60)
    var serialHex = ""

    func serialNumber() throws -> Certificate.SerialNumber {
        guard notBefore < notAfter else { throw TokenFailure.message("The certificate expiry must be after its start date.") }
        guard !serialHex.isEmpty else { return .init() }
        let bytes = try CertificateOptions.hexBytes(serialHex)
        guard bytes.count <= 20, bytes.first.map({ $0 < 128 }) == true, bytes.contains(where: { $0 != 0 }) else {
            throw TokenFailure.message("The serial number must be positive, at most 20 bytes, with its highest bit clear.")
        }
        return .init(bytes: bytes)
    }
}
