import SwiftUI

struct ContentView: View {
    @Bindable var model: TokenModel
    @State private var selection: Section = .identity
    @State private var confirmingDeletion = false
    @State private var keyPendingDeletion: StoredKey?
    @State private var showingNewKey = false
    @Environment(\.scenePhase) private var scenePhase
    @FocusState private var commonNameFocused: Bool
    @FocusState private var countryFocused: Bool

    private enum Section: String, CaseIterable, Identifiable {
        case identity = "Identity"
        case key = "Private Key"
        case request = "Certificates"

        var id: Self { self }
        var symbol: String {
            switch self {
            case .identity: "person.crop.rectangle"
            case .key: "key.horizontal"
            case .request: "doc.badge.plus"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                SwiftUI.Section("Keys (\(model.keys.count))") {
                    if model.keys.isEmpty {
                        Text("No stored keys").foregroundStyle(.secondary)
                    }
                    ForEach(model.keys) { key in
                        keyRow(key)
                    }

                }
                SwiftUI.Section("Manage selected key") {
                    ForEach(Section.allCases) { section in
                        Label(section.rawValue, systemImage: section.symbol).tag(section)
                    }
                }
            }
            .disabled(model.isBusy)
            .navigationTitle("Secure Enclave")
            .navigationSplitViewColumnWidth(min: 235, ideal: 275, max: 360)
            .safeAreaInset(edge: .bottom) {
                Label("On this Mac", systemImage: "desktopcomputer")
                    .font(.caption).foregroundStyle(.secondary)
                    .padding()
            }
        } detail: {
            ScrollViewReader { proxy in
                Form {
                    SwiftUI.Section("Selected key") {
                        Text(model.keys.isEmpty ? "Create a key using Add Key in the toolbar." : model.keyName)
                            .textSelection(.enabled)
                        if model.keyState.exists {
                            HStack {
                                Button("Remove Identity", systemImage: "person.crop.rectangle.badge.minus") {
                                    Task { await model.unloadToken() }
                                }
                                .disabled(!model.tokenLoaded || !model.driverAvailable)
                                .help("Remove the certificate and published identity; keep the private key")
                                Spacer()
                                Button("Delete Key…", systemImage: "trash", role: .destructive) {
                                    requestDeletion(of: StoredKey(id: model.tag, hardwareBacked: model.keyState.hardwareBacked))
                                }
                                .disabled(!model.driverAvailable)
                            }
                        }
                        if model.keys.count > 1 {
                            Text("Switch keys in the sidebar. Other loaded identities remain available.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    switch selection {
                    case .identity: identityContent
                    case .key: keyContent
                    case .request: requestContent(proxy: proxy)
                    }
                }
                .formStyle(.grouped)
                .disabled(model.isBusy)
                .navigationTitle(selection.rawValue)
                .safeAreaInset(edge: .bottom) {
                    HStack(spacing: 10) {
                        if model.isBusy { ProgressView().controlSize(.small) }
                        Text(model.isBusy ? "Working…" : model.status)
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(12)
                    .background(.bar)
                    .accessibilityElement(children: .combine)
                }
            }
        }
        .frame(minWidth: 850, minHeight: 620)
        .sheet(isPresented: $showingNewKey) { NewKeyView(model: model) }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button("Add Key", systemImage: "plus") { showingNewKey = true }
                    .disabled(model.isBusy || !model.enclaveAvailable)
                    .help("Create a new Secure Enclave key")
                Button("Import Certificate", systemImage: "square.and.arrow.down") {
                    Task { await model.importCertificate() }
                }
                .disabled(!model.canUseKey || !model.driverAvailable || model.isBusy)
                .help("Import a certificate for the selected key and load its identity")
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await model.refresh() } }
                    .disabled(model.isBusy)
                    .help("Refresh the key list and identity status")
            }
        }
        .task { await model.refresh() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { Task { await model.refresh() } }
        }
        .alert("Operation failed", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .confirmationDialog("Delete “\(keyPendingDeletion?.name ?? "")”?", isPresented: $confirmingDeletion,
                            titleVisibility: .visible, presenting: keyPendingDeletion) { key in
            Button("Delete Key", role: .destructive) {
                Task { await model.deleteKey(tag: key.id) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { key in
            Text("This permanently deletes “\(key.name)” and unloads its identity. Its certificates will no longer work. Other keys are kept. This cannot be undone.")
        }
    }

    private func keyRow(_ key: StoredKey) -> some View {
        Button {
            Task { await model.selectKey(tag: key.id) }
        } label: {
            keyRowLabel(key)
        }
        .buttonStyle(.plain)
        .help(key.name)
        .accessibilityLabel("\(key.name), \(key.id == model.tag ? "selected" : "select key")")
        .listRowBackground(key.id == model.tag ? Color.accentColor.opacity(0.12) : Color.clear)
        .contextMenu {
            Button("Delete Key…", systemImage: "trash", role: .destructive) {
                requestDeletion(of: key)
            }
            .disabled(!model.driverAvailable || model.isBusy)
        }
    }

    private func keyRowLabel(_ key: StoredKey) -> some View {
        HStack(spacing: 8) {
            Image(systemName: key.id == model.tag ? "checkmark.circle.fill" : "key.horizontal")
                .foregroundStyle(key.id == model.tag ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text(key.name).lineLimit(1).truncationMode(.middle)
                Text(!key.hardwareBacked ? "Legacy software key" :
                     (model.publishedTags.contains(key.id) ? "Identity loaded" : "No certificate loaded"))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    private func requestDeletion(of key: StoredKey) {
        keyPendingDeletion = key
        confirmingDeletion = true
    }

    @ViewBuilder private var identityContent: some View {
        SwiftUI.Section {
            HStack(spacing: 16) {
                Image(systemName: model.tokenLoaded && model.canUseKey ? "checkmark.shield.fill" : "shield.lefthalf.filled")
                    .font(.system(size: 36)).foregroundStyle(.tint)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    Text(model.identityStatus).font(.title2.weight(.semibold))
                    Text("Use a hardware-protected identity with apps that support smart cards.")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 8)
            LabeledContent("Secure Enclave", value: model.enclaveAvailable ? "Available" : "Unavailable")
            LabeledContent("Token extension", value: model.driverAvailable ? "Available" : "Unavailable")
            LabeledContent("Published items", value: "\(model.itemCount)")
            if !model.driverAvailable {
                Text("Run a signed build of the app. If necessary, enable SecureEnclaveTokenExtension in System Settings → General → Login Items & Extensions → Smart Card Readers, then refresh.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
        SwiftUI.Section("Certificate") {
            if model.tokenLoaded {
                LabeledContent("Subject", value: model.certificateName)
                Button("Export Certificate…") { Task { await model.exportCertificate() } }
                Text("Importing another certificate replaces the current certificate after checking that it matches your key.")
                    .foregroundStyle(.secondary)
            } else {
                Text("Create a self-signed certificate in Certificates, or import a matching certificate issued by your certificate authority.")
                    .foregroundStyle(.secondary)
                Button("Import Certificate…") { Task { await model.importCertificate() } }
                    .disabled(!model.canUseKey || !model.driverAvailable)
            }
            Text("Accepts a single DER or PEM certificate. Remove Identity keeps the private key. Export the certificate first if you want to import it again later.")
                .font(.caption).foregroundStyle(.secondary)
        }
        SwiftUI.Section("Get started") {
            Button("1. Create or inspect your private key") { selection = .key }
            Button("2. Create a signing request or self-signed certificate") { selection = .request }
        }
    }

    @ViewBuilder private var keyContent: some View {
        SwiftUI.Section("P-256 private key") {
            LabeledContent("Status", value: model.keyState.exists ? (model.keyState.hardwareBacked ? "Stored in Secure Enclave" : "Legacy software key") : "Not created")
            Text("A Secure Enclave private key stays on this Mac and cannot be exported or restored from a backup.")
                .foregroundStyle(.secondary)
            if model.keyState.exists {
                if !model.keyState.hardwareBacked {
                    Text("An older version created this key in software. It is preserved, but cannot be used as a Secure Enclave identity. Only delete it when you no longer need it.")
                        .foregroundStyle(.orange)
                }
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Public key fingerprint (SHA-256)")
                        Spacer()
                        Button("Copy", systemImage: "doc.on.doc") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(model.keyState.fingerprint, forType: .string)
                        }
                        .help("Copy the complete SHA-256 fingerprint")
                    }
                    ScrollView(.horizontal) {
                        Text(model.keyState.fingerprint)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                            .fixedSize(horizontal: true, vertical: false)
                            .textSelection(.enabled)
                    }
                }
                Button("Export Public Key…") { Task { await model.exportPublicKey() } }
            } else {
                Button("New Key…", systemImage: "plus") { showingNewKey = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.enclaveAvailable)

            }
        }
    }

    @ViewBuilder private func requestContent(proxy: ScrollViewProxy) -> some View {
        SwiftUI.Section {
            Picker("Create", selection: $model.output) {
                ForEach(TokenModel.Output.allCases) { Text($0.rawValue).tag($0) }
            }
            Text(model.output == .request
                 ? "Create a PKCS#10 request to send to your certificate authority. Requested extensions may be changed or rejected by the authority."
                 : "Create an X.509 certificate signed by this key. It is not automatically trusted; configure trust explicitly in clients that use it.")
                .foregroundStyle(.secondary)
            if !model.canUseKey {
                Label("Create a Secure Enclave key first.", systemImage: "info.circle")
            }
        }
        SwiftUI.Section("Subject") {
            CertificateTextField("Common name (required)", text: $model.subject.commonName, prompt: "e.g. Alex Smith or example.com", focus: $commonNameFocused)
                .id("common-name")
            if let error = model.subject.commonNameValidationError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            CertificateTextField("Organization", text: $model.subject.organization, prompt: "e.g. Example Company")
            CertificateTextField("Organizational units", text: $model.subject.organizationalUnit, prompt: "e.g. Engineering; Security")
            CertificateTextField("Email addresses", text: $model.subject.emailAddress, prompt: "e.g. alex@example.com")
            Text("Separate multiple organizational units or email addresses with semicolons.")
                .font(.caption).foregroundStyle(.secondary)
        }
        SwiftUI.Section("Location") {
            CertificateTextField("City or locality", text: $model.subject.locality, prompt: "e.g. New York")
            CertificateTextField("State or province", text: $model.subject.province, prompt: "e.g. New York")
            CertificateTextField("Country (two-letter code)", text: $model.subject.country, prompt: "e.g. US", focus: $countryFocused)
                .id("country")
            if let error = model.subject.countryValidationError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        }
        SwiftUI.Section("Additional subject attributes") {
            ForEach($model.subject.customAttributes) { $attribute in
                VStack(alignment: .leading) {
                    HStack {
                        CertificateTextField("OID (e.g. 2.5.4.5)", text: $attribute.oid, prompt: "e.g. 2.5.4.5")
                        Picker("Encoding", selection: $attribute.encoding) {
                            ForEach(CustomSubjectAttribute.Encoding.allCases) { Text($0.rawValue).tag($0) }
                        }
                        Button("Remove", systemImage: "minus.circle", role: .destructive) {
                            model.subject.customAttributes.removeAll { $0.id == attribute.id }
                        }.labelStyle(.iconOnly)
                    }
                    CertificateTextField("Value", text: $attribute.value, prompt: "Enter the attribute value", multiline: true)
                }
            }
            Button("Add Subject Attribute", systemImage: "plus") { model.subject.customAttributes.append(.init()) }
        }
        CertificateOptionsView(options: $model.certificateOptions)
        if model.output == .selfSigned {
            SwiftUI.Section("Validity and serial number") {
                DatePicker("Valid from", selection: $model.validity.notBefore)
                DatePicker("Valid until", selection: $model.validity.notAfter)
                CertificateTextField("Serial number (hex; blank generates a random value)", text: $model.validity.serialHex, prompt: "Leave blank for a random serial number")
            }
        }
        SwiftUI.Section {
            if let error = model.certificateValidationError {
                Label(error, systemImage: "exclamationmark.circle")
                    .font(.callout).foregroundStyle(.red)
                if model.subject.commonNameValidationError != nil {
                    Button("Enter Common Name") {
                        proxy.scrollTo("common-name", anchor: .center)
                        commonNameFocused = true
                    }
                } else if model.subject.countryValidationError != nil {
                    Button("Correct Country Code") {
                        proxy.scrollTo("country", anchor: .center)
                        countryFocused = true
                    }
                }
            }
            if model.output == .request {
                Button("Save Signing Request…", systemImage: "doc.badge.plus") {
                    Task { await model.exportSigningRequest() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canUseKey || model.certificateValidationError != nil)
            } else {
                Button("Create Self-Signed Certificate", systemImage: "person.crop.rectangle") {
                    Task {
                        if await model.createSelfSignedIdentity() { selection = .identity }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!model.canUseKey || !model.driverAvailable || model.certificateValidationError != nil)
                Text("Automatically associates the certificate with this key and loads its identity. Replaces this key’s current certificate. Export it from Identity afterward.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

private struct CertificateOptionsView: View {
    @Binding var options: CertificateOptions

    private func usageBinding(_ usage: StandardExtendedKeyUsage) -> Binding<Bool> {
        Binding {
            options.extendedKeyUsage.split(whereSeparator: { $0.isWhitespace || $0 == "," || $0 == ";" })
                .contains(Substring(usage.rawValue))
        } set: { selected in
            var values = options.extendedKeyUsage.split(whereSeparator: { $0.isWhitespace || $0 == "," || $0 == ";" }).map(String.init)
            values.removeAll { $0 == usage.rawValue }
            if selected { values.append(usage.rawValue) }
            options.extendedKeyUsage = values.joined(separator: "\n")
        }
    }

    var body: some View {
        SwiftUI.Section("Key usage") {
            Toggle("Digital signature", isOn: $options.digitalSignature).toggleStyle(.checkbox)
            Toggle("Key agreement", isOn: $options.keyAgreement).toggleStyle(.checkbox)
        }
        SwiftUI.Section("Extended key usage") {
            ForEach(StandardExtendedKeyUsage.allCases) { usage in
                Toggle(isOn: usageBinding(usage)) {
                    HStack {
                        Text(usage.title)
                        Spacer()
                        Text(usage.rawValue).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.checkbox)
            }
            ForEach($options.customExtendedKeyUsages) { $usage in
                HStack(alignment: .bottom) {
                    CertificateTextField("Custom usage OID", text: $usage.oid, prompt: "e.g. 1.3.6.1.4.1.55555.1")
                    Button("Remove custom usage", systemImage: "minus.circle", role: .destructive) {
                        options.customExtendedKeyUsages.removeAll { $0.id == usage.id }
                    }.labelStyle(.iconOnly).padding(.bottom, 8)
                }
            }
            Button("Add Custom OID", systemImage: "plus") { options.customExtendedKeyUsages.append(.init()) }
            Text("Select the purposes this certificate should support. Uncheck all and remove custom OIDs to omit this extension.")
                .font(.caption).foregroundStyle(.secondary)
        }
        SwiftUI.Section("Subject alternative names") {
            CertificateTextField("Names and addresses", text: $options.subjectAlternativeNames,
                                 prompt: "DNS:example.com\nemail:alex@example.com\nIP:192.0.2.1", multiline: true)
            Text("One per line, prefixed with DNS:, email:, URI: or IP:.")
                .font(.caption).foregroundStyle(.secondary)
        }
        SwiftUI.Section("Custom X.509 extensions") {
            ForEach($options.customExtensions) { $item in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        CertificateTextField("Extension OID", text: $item.oid, prompt: "e.g. 1.3.6.1.4.1.55555.1")
                        Toggle("Critical", isOn: $item.critical).toggleStyle(.checkbox)
                        Button("Remove", systemImage: "minus.circle", role: .destructive) {
                            options.customExtensions.removeAll { $0.id == item.id }
                        }.labelStyle(.iconOnly)
                    }
                    CertificateTextField("DER value (hex)", text: $item.valueHex, prompt: "e.g. 0C0568656C6C6F", multiline: true)
                        .font(.system(.body, design: .monospaced))
                }
            }
            Button("Add Extension", systemImage: "plus") { options.customExtensions.append(.init()) }
            Text("Supply the inner DER value, without the outer OCTET STRING wrapper. For example, UTF8String “hello” is 0C0568656C6C6F. Disable a standard preset before using its OID here. Unknown critical extensions require client support.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

// Explicit labels and input borders remain visible in a grouped macOS Form.
private struct CertificateTextField: View {
    let title: String
    @Binding var text: String
    let prompt: String
    var multiline = false
    var focus: FocusState<Bool>.Binding?

    init(_ title: String, text: Binding<String>, prompt: String, multiline: Bool = false, focus: FocusState<Bool>.Binding? = nil) {
        self.title = title
        self._text = text
        self.prompt = prompt
        self.multiline = multiline
        self.focus = focus
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout.weight(.medium))
            input
                .labelsHidden()
                .textFieldStyle(.plain)
                .lineLimit(multiline ? 3...8 : 1...1)
                .padding(9)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color(nsColor: .separatorColor), lineWidth: 1))
                .accessibilityLabel(title)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 3)
    }

    @ViewBuilder private var input: some View {
        if let focus {
            TextField("", text: $text, prompt: Text(prompt), axis: multiline ? .vertical : .horizontal)
                .focused(focus)
        } else {
            TextField("", text: $text, prompt: Text(prompt), axis: multiline ? .vertical : .horizontal)
        }
    }
}

private struct NewKeyView: View {
    @Bindable var model: TokenModel
    @State private var name = ""
    @Environment(\.dismiss) private var dismiss

    private var duplicate: Bool { model.keys.contains { $0.id == Data(name.utf8) } }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("New Secure Enclave Key").font(.title2.weight(.semibold))
            CertificateTextField("Key name", text: $name, prompt: "e.g. Work VPN or Personal signing")
            Text("Choose a unique name. The CLI uses this name as the key tag.")
                .font(.caption).foregroundStyle(.secondary)
            Picker("Key availability", selection: $model.accessibility) {
                ForEach(KeyAccessibility.allCases) { Text($0.title).tag($0) }
            }
            Picker("Authentication", selection: $model.authentication) {
                ForEach(KeyAuthentication.allCases) { Text($0.title).tag($0) }
            }
            Text("Availability and authentication are fixed when the key is created.")
                .font(.caption).foregroundStyle(.secondary)
            if duplicate { Text("A key with this name already exists.").foregroundStyle(.red) }
            if let error = model.errorMessage { Text(error).foregroundStyle(.red) }
            HStack {
                if model.isBusy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Generate Key") {
                    Task { if await model.generateKey(named: name) { dismiss() } }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(duplicate || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !model.enclaveAvailable)
            }
        }
        .padding(24)
        .frame(width: 460)
        .disabled(model.isBusy)
        .interactiveDismissDisabled(model.isBusy)
    }
}
