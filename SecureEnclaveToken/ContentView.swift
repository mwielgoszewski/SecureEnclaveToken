//
//  ContentView.swift
//  SecureEnclaveToken
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import SwiftUI
import CryptoKit
import CryptoTokenKit
import CertificateSigningRequest

struct ContentView: View {
    @State private var keysIsEmpty = false
    @State private var loadButton = "Query Token"
    @State private var keysLoaded = 0
    @State private var certificateLabel = ""
    @State private var keyLabel = ""
    @State private var generateKeyDescription = ""
    @State private var showDeleteConfirmation = false
    @State private var commonName = ""
    @State private var emailAddress = ""
    @State private var organizationUnitName = ""
    @State private var organizationName = ""
    @State private var localityName = ""
    @State private var stateOrProvinceName = ""
    @State private var countryName = ""
    @State private var keyAccessibilityFlags = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    @State private var keyAccessControlFlags = 0

    let driverConfig = TKTokenDriver.Configuration.driverConfigurations["com.mwielgoszewski.SecureEnclaveToken.SecureEnclaveTokenExtension"]

    // A unique, persistent identifier for this token.
    // This value is typically generated from the serial number of the target hardware.
    var tokenID: String {
        let fallbackInstanceID = "819D11D7A8F7D609F236F529996E9F4C"
        let platformExpert = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice") )

        guard platformExpert > 0 else {
            return fallbackInstanceID
        }

        guard let serialNumber = (IORegistryEntryCreateCFProperty(platformExpert, kIOPlatformSerialNumberKey as CFString, kCFAllocatorDefault, 0).takeUnretainedValue() as? String) else {
            return fallbackInstanceID
        }

        IOObjectRelease(platformExpert)

        let serialHash = SHA256.hash(data: serialNumber.data(using: .utf8)!).hexStr.dropLast(32)
        return String(serialHash)
    }

    var tokenConfig: TKToken.Configuration {
        loadTokenConfig()
    }

    func loadTokenConfig() -> TKToken.Configuration {
        if driverConfig!.tokenConfigurations.isEmpty {
            driverConfig?.addTokenConfiguration(for: tokenID)
        }
        var tokenConfig = driverConfig!.tokenConfigurations[tokenID]
        if tokenConfig == nil {
            tokenConfig = driverConfig?.addTokenConfiguration(for: tokenID)
        }
        return tokenConfig!
    }

    func unloadTokenConfig() {
        driverConfig!.removeTokenConfiguration(for: tokenID)
    }

    func clearAllTokenConfigs() {
        for tokenConfigurationID in driverConfig!.tokenConfigurations.keys {
            print("Removing token configuration for \(tokenConfigurationID)")
            driverConfig!.removeTokenConfiguration(for: tokenConfigurationID)
        }
    }

    var body: some View {
        let tag = "com.mwielgoszewski.SecureEnclaveToken.Key".data(using: .utf8)!

        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Button(action: {
                    if tokenConfig.keychainItems.isEmpty {
                        let panel = NSOpenPanel()
                        panel.allowsMultipleSelection = false
                        panel.canChooseDirectories = false
                        panel.allowedFileTypes = ["cer"]
                        if panel.runModal() == .OK {
                            let certificate = panel.url!.absoluteURL
                            _ = loadCertificateForTagIntoTokenConfig(certificatePath: certificate, tag: tag, tokenConfig: tokenConfig)
                        }
                    } else if self.loadButton == "Unload Token" {
                        tokenConfig.keychainItems.removeAll()
                    }
                    self.loadButton = tokenConfig.keychainItems.isEmpty ? "Load Token" : "Unload Token"
                    keysLoaded = tokenConfig.keychainItems.count

                    if keysLoaded > 0 {
                        do {
                            let tkcert = try tokenConfig.certificate(for: tag)
                            let tkkey  = try tokenConfig.key(for: tag)
                            certificateLabel = " • \(tkcert.label ?? "")"
                            keyLabel = " • \(tkkey.label ?? "")"
                        } catch {
                        }
                    } else {
                        certificateLabel = ""
                        keyLabel = ""
                    }

                }) {
                    Text(loadButton)
                }
                VStack(alignment: .leading) {
                    Text("\(keysLoaded) token keychain items loaded")
                    Text(certificateLabel)
                    Text(keyLabel)
                }
            }

            HStack(alignment: .top) {
                Button(action: {
                    var secKey = loadSecureEnclaveKey(tag: tag)
                    if secKey != nil {
                        generateKeyDescription = "Found key: \(secKey.debugDescription)"
                    } else {
                        secKey = generateKeyInEnclave(tag: tag, accessibility: keyAccessibilityFlags, accessControlFlags: keyAccessControlFlags)
                        generateKeyDescription = "Generated key: \(secKey.debugDescription)"
                    }
                }) {
                    Text("Generate Key")
                }

                VStack(alignment: .leading) {
                    Picker(selection: $keyAccessibilityFlags, label: Text("Access:")) {
                        Text("After first unlock").tag(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
                        Text("When unlocked").tag(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
                    }

                    Picker(selection: $keyAccessControlFlags, label: Text("Require:")) {
                        Text("Biometric").tag(3)
                        Text("Passcode").tag(2)
                        Text("User Presence (Biometric OR Passcode)").tag(1)
                        Text("No additional security").tag(0)
                    }

                    Text(generateKeyDescription)
                }
            }

            HStack {
                Button(action: {
                    self.showDeleteConfirmation = true
                }) {
                    Text("Delete Key")
                }
                .alert(isPresented: $showDeleteConfirmation) {
                    Alert(title: Text("Are you sure you want to delete this key?"), message: Text("Deleted keys cannot be recovered."),
                          primaryButton: .cancel(),
                          secondaryButton: .destructive(Text("Delete Key"), action: {
                            if deleteSecureEnclaveKey(tag: tag) {
                                print("Deleted key from enclave, unloading token configuration")
                                unloadTokenConfig()
                            }
                          })
                    )
                }
            }

            HStack {
                Button(action: {
                    let secKey = loadSecureEnclaveKey(tag: tag)
                    let publicKey = SecKeyCopyPublicKey(secKey!)

                    var error: Unmanaged<CFError>?
                    let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
                    let bytes: Data = ixy! as Data

                    // seq / seq / id-ecPublicKey / prime256v1 asn.1
                    var der = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA=")!
                    // EC keys should be in ANSI X9.63, uncompressed byte string 04 || X || Y
                    der.append(bytes)
                    print(der.base64EncodedString())

                    let panel = NSSavePanel()
                    // default filename to <tag>.pub
                    panel.nameFieldStringValue = String(decoding: tag, as: UTF8.self) + ".pub"
                    if panel.runModal() == .OK {
                        let exportFilename = panel.url!.absoluteURL
                        do {
                            try der.write(to: exportFilename)
                        } catch {
                            print("Failed to write to \(exportFilename)")
                        }
                    }
                }) {
                    Text("Export Public Key")
                }
            }

            HStack(alignment: .top) {
                Button(action: {
                    let secKey = loadSecureEnclaveKey(tag: tag)
                    if secKey != nil {
                        let publicKey = SecKeyCopyPublicKey(secKey!)

                        var error: Unmanaged<CFError>?
                        let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
                        let publicKeyBits: Data = ixy! as Data

                        let savePanel = NSSavePanel()
                        // default filename to <tag>.req
                        savePanel.nameFieldStringValue = String(decoding: tag, as: UTF8.self) + ".req"
                        if savePanel.runModal() == .OK {
                            let exportFilename = savePanel.url!
                            do {
                                let keyAlgorithm = KeyAlgorithm.ec(signatureType: .sha256)
                                let csr = CertificateSigningRequest.init(
                                    commonName: commonName,
                                    organizationName: organizationName,
                                    organizationUnitName: organizationUnitName,
                                    countryName: countryName,
                                    stateOrProvinceName: stateOrProvinceName,
                                    localityName: localityName,
                                    emailAddress: emailAddress,
                                    description: nil,
                                    keyAlgorithm: keyAlgorithm)

                                let pem = csr.buildCSRAndReturnString(publicKeyBits, privateKey: secKey!, publicKey: publicKey)
                                try pem?.data(using: .ascii)!.write(to: exportFilename)
                            } catch {
                                print("Failed to write to \(exportFilename)")
                            }
                        }
                    }

                }) {
                    Text("Generate Signing Request")
                }

                VStack(alignment: .leading) {
                    Text("Enter fields below:")
                    TextField("Common Name", text: $commonName)
                    TextField("Email Address (delimit using semicolon)", text: $emailAddress)
                    TextField("Organizational Unit (delimit using semicolon)", text: $organizationUnitName)
                    TextField("Organization", text: $organizationName)
                    TextField("Locality", text: $localityName)
                    TextField("State or Province", text: $stateOrProvinceName)
                    TextField("Country", text: $countryName)
                }

            }
        }
        .padding()

    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
