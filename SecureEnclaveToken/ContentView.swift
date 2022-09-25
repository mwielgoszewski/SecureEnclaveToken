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

    @State private var genTag = ""
    @State private var csrTag = ""
    @State private var deleteTag = ""
    @State private var exportTag = ""

    let queryTokenTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var tokenConfig: TKToken.Configuration? {
        loadTokenConfig()
    }

    var keyTags: [String] {
        var item: AnyObject?

        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                                    kSecReturnRef as String: true,
                                    kSecReturnAttributes as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return []
        }

        var items: [String] = []

        for attr in item as! [NSDictionary] {
            let atag = attr[kSecAttrApplicationTag as String] as? Data
            items.append(String(data: atag!, encoding: .utf8)!)
        }
        return items
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack {
                    Text("SecureEnclaveToken; see cli help for more options")
                }
            }
            HStack(alignment: .top) {
                VStack(alignment: .leading) {
                    Text("\(keysLoaded) token keychain items loaded")
                    Text(certificateLabel)
                    Text(keyLabel)
                }.onReceive(queryTokenTimer, perform: { _ in
                    keysLoaded = tokenConfig?.keychainItems.count ?? 0
                })
            }

            HStack(alignment: .top) {
                VStack(alignment: .leading) {
                    Button(action: {
                        let tag = genTag.data(using: .utf8)!
                        var secKey = loadSecureEnclaveKey(tag: tag)
                        if secKey != nil {
                            generateKeyDescription = "Found key: \(secKey.debugDescription)"
                        } else {
                            secKey = generateKeyInEnclaveFromUi(tag: tag, accessibility: keyAccessibilityFlags, accessControlFlags: keyAccessControlFlags)
                            generateKeyDescription = "Generated key: \(secKey.debugDescription)"
                        }
                    }) {
                        Text("Generate Key")
                    }
                }.padding(15)

                VStack(alignment: .leading) {
                    TextField("Tag", text: $genTag)

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
                VStack(alignment: .leading) {
                    Button(action: {
                        self.showDeleteConfirmation = true
                    }) {
                        Text("Delete Key")
                    }
                    .alert(isPresented: $showDeleteConfirmation) {
                        Alert(title: Text("Are you sure you want to delete this key?"), message: Text("Deleted keys cannot be recovered."),
                              primaryButton: .cancel(),
                              secondaryButton: .destructive(Text("Delete Key"), action: {
                            let tag = deleteTag.data(using: .utf8)!
                            if deleteSecureEnclaveKey(tag: tag) {
                                print("Deleted key from enclave, unloading token configuration")
                                unloadTokenConfig()
                            }
                        })
                        )
                    }
                }.padding(20)

                VStack {
                    Picker(selection: $deleteTag, label: Text("")) {
                        ForEach(0 ..< keyTags.count, id: \.self) { index in
                            Text(self.keyTags[index]).tag(self.keyTags[index])
                        }
                    }
                }
            }

            HStack {
                VStack(alignment: .leading) {
                    Button(action: {
                        let tag = exportTag.data(using: .utf8)!
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

                VStack {
                    Picker(selection: $exportTag, label: Text("")) {
                        ForEach(0 ..< keyTags.count, id: \.self) { index in
                            Text(self.keyTags[index]).tag(self.keyTags[index])
                        }
                    }
                }
            }

            HStack(alignment: .top) {
                VStack {
                    Button(action: {
                        let tag = csrTag.data(using: .utf8)!
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
                                        organizationUnitName: organizationUnitName.split(separator: ";").map(String.init),
                                        countryName: countryName,
                                        stateOrProvinceName: stateOrProvinceName,
                                        localityName: localityName,
                                        emailAddress: emailAddress.split(separator: ";").map(String.init),
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
                        Text("Generate CSR")
                    }
                }.padding(15)

                VStack(alignment: .leading) {
                    Picker(selection: $csrTag, label: Text("For key:")) {
                        ForEach(0 ..< keyTags.count, id: \.self) { index in
                            Text(self.keyTags[index]).tag(self.keyTags[index])
                        }
                    }
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
