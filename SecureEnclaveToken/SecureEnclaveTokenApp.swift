import AppKit
import SwiftUI

struct SecureEnclaveTokenApp: App {
    @State private var model = TokenModel()

    var body: some Scene {
        Window("Secure Enclave Token", id: "main") {
            ContentView(model: model)
        }
        .defaultSize(width: 850, height: 650)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Import Certificate…") { Task { await model.importCertificate() } }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                    .disabled(!model.canUseKey || !model.driverAvailable || model.isBusy)
                Button("Refresh Status") { Task { await model.refresh() } }
                    .keyboardShortcut("r")
                    .disabled(model.isBusy)
            }
        }

        MenuBarExtra("Secure Enclave Token", systemImage: "key.horizontal") {
            TokenMenuView(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}

private struct TokenMenuView: View {
    @Bindable var model: TokenModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Secure Enclave Token", systemImage: "key.horizontal.fill")
                .font(.headline)
            Label(model.identityStatus, systemImage: model.tokenLoaded && model.canUseKey ? "checkmark.shield.fill" : "shield")
                .foregroundStyle(model.tokenLoaded && model.canUseKey ? .green : .secondary)
            if !model.certificateName.isEmpty {
                Text(model.certificateName).font(.callout).lineLimit(2)
            }
            if let error = model.errorMessage {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            Button("Open Secure Enclave Token") {
                openWindow(id: "main")
                NSApplication.shared.activate()
            }
            .buttonStyle(.borderedProminent)
            .frame(maxWidth: .infinity)
            Divider()
            HStack {
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await model.refresh() } }
                Spacer()
                if model.isBusy { ProgressView().controlSize(.small) }
                Button("Remove Identity") { Task { await model.unloadToken() } }
                    .disabled(!model.tokenLoaded || !model.driverAvailable)
            }
            .disabled(model.isBusy)
            Button("Quit Secure Enclave Token") { NSApplication.shared.terminate(nil) }
                .keyboardShortcut("q")
        }
        .padding(20)
        .frame(width: 340)
        .task { await model.refresh() }
    }
}
