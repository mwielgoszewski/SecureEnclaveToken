import AppKit
import CryptoKit
import CryptoTokenKit
import Observation
import UniformTypeIdentifiers
import X509

actor TokenWorker {
    struct KeyState: Sendable {
        var exists = false
        var hardwareBacked = false
        var fingerprint = ""
    }

    func storedKeys() throws -> [StoredKey] { try TokenSecurity.storedKeys() }

    func keyState(tag: Data) throws -> KeyState {
        guard let key = try TokenSecurity.loadKey(tag: tag) else { return KeyState() }
        let publicKey = try TokenSecurity.publicKey(for: key)
        let fingerprint = SHA256.hash(data: try TokenSecurity.externalRepresentation(of: publicKey))
            .map { String(format: "%02x", $0) }.joined(separator: ":")
        return KeyState(exists: true, hardwareBacked: TokenSecurity.isHardwareBacked(key), fingerprint: fingerprint)
    }

    func generate(tag: Data, accessibility: KeyAccessibility, authentication: KeyAuthentication) throws {
        try TokenSecurity.generateKey(tag: tag, accessibility: accessibility, authentication: authentication)
    }
    func delete(tag: Data) throws { try TokenSecurity.deleteKey(tag: tag) }

    func certificateData(tag: Data, subject: CertificateSubject, options: CertificateOptions,
                         validity: SelfSignedOptions?) throws -> Data {
        let key = try TokenSecurity.requireKey(tag: tag)
        if let validity { return try subject.selfSignedCertificate(for: key, options: options, validity: validity) }
        return try subject.signingRequest(for: key, options: options)
    }

    func export(to url: URL, tag: Data, subject: CertificateSubject?, options: CertificateOptions) throws {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        let data: Data
        if let subject {
            data = try certificateData(tag: tag, subject: subject, options: options, validity: nil)
        } else {
            guard let key = try TokenSecurity.loadKey(tag: tag) else { throw TokenFailure.message("No key is available to export.") }
            data = try TokenSecurity.subjectPublicKeyInfo(TokenSecurity.publicKey(for: key))
        }
        try data.write(to: url, options: .atomic)
    }

    func readCertificate(at url: URL, tag: Data) throws -> Data {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        let certificate = try TokenSecurity.certificate(from: Data(contentsOf: url))
        let publicKey = try TokenSecurity.publicKey(for: TokenSecurity.requireKey(tag: tag))
        try TokenSecurity.validate(certificate, matches: publicKey)
        return SecCertificateCopyData(certificate) as Data
    }
}

@MainActor @Observable
final class TokenModel {
    enum Output: String, CaseIterable, Identifiable {
        case request = "Signing request", selfSigned = "Self-signed certificate"
        var id: Self { self }
    }
    private(set) var tag = TokenConstants.keyTag
    private(set) var keys: [StoredKey] = []
    private(set) var publishedTags = Set<Data>()
    var keyName: String { StoredKey(id: tag, hardwareBacked: keyState.hardwareBacked).name }
    private(set) var keyState = TokenWorker.KeyState()
    private(set) var driverAvailable = false
    private(set) var itemCount = 0
    private(set) var certificateName = ""
    private(set) var isBusy = false
    private(set) var status = "Checking your identity…"
    var errorMessage: String?
    var authentication = KeyAuthentication.userPresence
    var accessibility = KeyAccessibility.whenUnlocked
    var subject = CertificateSubject()
    var certificateOptions = CertificateOptions()
    var validity = SelfSignedOptions()
    var output = Output.request

    let enclaveAvailable = SecureEnclave.isAvailable
    private let worker = TokenWorker()
    var tokenLoaded: Bool { itemCount > 0 }
    var canUseKey: Bool { keyState.exists && keyState.hardwareBacked }
    var identityStatus: String {
        if !driverAvailable { return "Extension unavailable" }
        if tokenLoaded && canUseKey { return "Identity loaded" }
        if tokenLoaded { return "Identity needs attention" }
        return canUseKey ? "Ready for a certificate" : "No identity loaded"
    }
    var certificateValidationError: String? {
        do {
            _ = try subject.distinguishedName()
            _ = try certificateOptions.extensions(selfSigned: output == .selfSigned)
            if output == .selfSigned { _ = try validity.serialNumber() }
            return nil
        } catch { return error.localizedDescription }
    }

    func selectKey(tag: Data) async {
        guard !isBusy, !tag.isEmpty else { return }
        self.tag = tag
        keyState = .init()
        itemCount = 0
        certificateName = ""
        await refresh()
    }

    private func updateState() async throws {
        driverAvailable = TokenRegistry.driver != nil
        keys = try await worker.storedKeys()
        if !keys.contains(where: { $0.id == tag }), let first = keys.first { tag = first.id }
        let allItems = driverAvailable ? try TokenRegistry.configuration()?.keychainItems ?? [] : []
        publishedTags = Set(allItems.compactMap { ($0 as? TKTokenKeychainCertificate)?.objectID as? Data })
        let items = allItems.filter { $0.objectID as? Data == tag }
        itemCount = items.count
        certificateName = items.compactMap { $0 as? TKTokenKeychainCertificate }.first?.label ?? ""
        keyState = try await worker.keyState(tag: tag)
    }
    func refresh() async { await perform(success: "Status refreshed.") {} }

    private func perform(success: String, operation: () async throws -> Void) async {
        guard !isBusy else { return }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            try await operation()
            try await updateState()
            status = success
        } catch {
            try? await updateState()
            status = "The operation could not be completed."
            errorMessage = error.localizedDescription
        }
    }

    func generateKey(named name: String) async -> Bool {
        guard !isBusy, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        let newTag = Data(name.utf8)
        let access = accessibility, auth = authentication
        await perform(success: "Your P-256 key was created in the Secure Enclave.") {
            try await worker.generate(tag: newTag, accessibility: access, authentication: auth)
            tag = newTag
        }
        return errorMessage == nil && tag == newTag && keyState.exists
    }
    func deleteKey(tag: Data) async {
        // Use the key captured by the confirmation, not a later sidebar selection.
        await perform(success: "The key was deleted and its identity unloaded.") {
            try TokenRegistry.remove(tag: tag)
            try await worker.delete(tag: tag)
        }
    }
    func unloadToken() async {
        await perform(success: "Identity removed. Your private key is still stored on this Mac.") {
            try TokenRegistry.remove(tag: tag)
        }
    }

    func importCertificate() async {
        guard !isBusy else { return }
        let panel = NSOpenPanel()
        panel.title = "Import a signed certificate"
        panel.prompt = "Import Certificate"
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = ["cer", "der", "pem", "crt"].compactMap { UTType(filenameExtension: $0) }
        isBusy = true
        let response = await panel.begin()
        isBusy = false
        guard response == .OK, let url = panel.url else { return }
        await perform(success: "Certificate imported. Your identity is available to CryptoTokenKit clients.") {
            let data = try await worker.readCertificate(at: url, tag: tag)
            try TokenRegistry.install(certificateData: data, tag: tag)
        }
    }

    func createSelfSignedIdentity() async -> Bool {
        guard !isBusy else { return false }
        let subject = subject, options = certificateOptions, validity = validity
        await perform(success: "Self-signed identity loaded. Trust must be configured separately by its clients.") {
            let data = try await worker.certificateData(tag: tag, subject: subject, options: options, validity: validity)
            try TokenRegistry.install(certificateData: data, tag: tag)
        }
        return errorMessage == nil && tokenLoaded
    }

    func exportCertificate() async {
        guard !isBusy else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "SecureEnclaveToken-certificate.pem"
        isBusy = true
        let response = await panel.begin()
        isBusy = false
        guard response == .OK, let url = panel.url else { return }
        await perform(success: "Saved \(url.lastPathComponent).") {
            guard let item = try TokenRegistry.configuration()?.certificate(for: tag) else {
                throw TokenFailure.message("No certificate is loaded for this key.")
            }
            let pem = try Certificate(TokenSecurity.certificate(from: item.data)).serializeAsPEM().pemString
            try Data(pem.utf8).write(to: url, options: .atomic)
        }
    }

    func exportPublicKey() async { await export(subject: nil) }
    func exportSigningRequest() async { await export(subject: subject) }
    private func export(subject: CertificateSubject?) async {
        guard !isBusy else { return }
        let options = certificateOptions
        let ext = subject == nil ? "der" : "csr"
        let panel = NSSavePanel()
        panel.title = subject == nil ? "Export public key" : "Save certificate signing request"
        panel.nameFieldStringValue = subject == nil ? "SecureEnclaveToken-public-key.der" : "SecureEnclaveToken.\(ext)"
        panel.allowedContentTypes = [UTType(filenameExtension: ext) ?? .data]
        isBusy = true
        let response = await panel.begin()
        isBusy = false
        guard response == .OK, let url = panel.url else { return }
        await perform(success: "Saved \(url.lastPathComponent).") {
            try await worker.export(to: url, tag: tag, subject: subject, options: options)
        }
    }
}
