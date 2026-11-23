import AppKit
import SwiftUI

struct SecureEnclaveTokenApp: App {
    @State private var model = TokenModel()

    var body: some Scene {
        Window("Secure Enclave Token", id: "main") {
            ContentView(model: model)
                .background(MainWindowLifecycle())
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
        .menuBarExtraStyle(.menu)
    }
}

// Observe only the main window, without replacing SwiftUI's window delegate.
// Closing a menu bar panel or a certificate dialog must not change app presence.
private struct MainWindowLifecycle: NSViewRepresentable {
    func makeNSView(context: Context) -> ObserverView { ObserverView() }
    func updateNSView(_ nsView: ObserverView, context: Context) {}

    final class ObserverView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            NotificationCenter.default.removeObserver(self)
            guard let window else { return }
            NotificationCenter.default.addObserver(
                self, selector: #selector(windowWillClose),
                name: NSWindow.willCloseNotification, object: window)
            NotificationCenter.default.addObserver(
                self, selector: #selector(windowDidBecomeKey),
                name: NSWindow.didBecomeKeyNotification, object: window)
        }

        @objc private func windowWillClose(_ notification: Notification) {
            NSApplication.shared.setActivationPolicy(.accessory)
        }

        @objc private func windowDidBecomeKey(_ notification: Notification) {
            NSApplication.shared.setActivationPolicy(.regular)
        }

        deinit { NotificationCenter.default.removeObserver(self) }
    }
}

private struct TokenMenuView: View {
    @Bindable var model: TokenModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.identityStatus)
        if !model.certificateName.isEmpty {
            Text(model.certificateName)
        }
        Divider()
        Button("Open Secure Enclave Token", systemImage: "macwindow") {
            NSApplication.shared.setActivationPolicy(.regular)
            openWindow(id: "main")
            NSApplication.shared.activate()
        }
        Button("Refresh Status", systemImage: "arrow.clockwise") {
            Task { await model.refresh() }
        }
        .disabled(model.isBusy)
        Button("Remove Selected Identity", systemImage: "person.crop.rectangle.badge.minus") {
            Task { await model.unloadToken() }
        }
        .disabled(!model.tokenLoaded || !model.driverAvailable || model.isBusy)
        Divider()
        Button("About Secure Enclave Token") {
            NSApplication.shared.orderFrontStandardAboutPanel(nil)
            NSApplication.shared.activate()
        }
        Button("Quit Secure Enclave Token", systemImage: "power") {
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}
