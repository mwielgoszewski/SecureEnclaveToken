//
//  SecureEnclaveTokenUtils.swift
//  SecureEnclaveToken
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import Foundation
import Security
import CryptoKit
import CryptoTokenKit

func generateKeyInEnclave(tag: Data, accessibility: CFString, accessControlFlags: Int) -> SecKey {
    print("Generating key ...")

    var flags: SecAccessControlCreateFlags

    switch accessControlFlags {
    case 1:
        flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.userPresence]
    case 2:
        flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.devicePasscode]
    case 3:
        flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.biometryAny]
    default:
        flags = [SecAccessControlCreateFlags.privateKeyUsage]
    }

    let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                 accessibility,
                                                 flags,
                                                 nil)! // ignore error

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: access
      ]
    ]

    var publicKey, privateKey: SecKey?

    let status = SecKeyGeneratePair(attributes as CFDictionary, &publicKey, &privateKey)

    print(status)
    print(privateKey!)
    print(publicKey!)

    var error: Unmanaged<CFError>?

    // Create a bogus signature of the data to prove biometric
    let signature = SecKeyCreateSignature(privateKey!,
                                          .ecdsaSignatureMessageX962SHA256,
                                          tag as CFData,
                                          &error) as Data?
    print("Signature: \(String(describing: signature))")

    let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
    print(ixy!)

    let bytes: Data = ixy! as Data
    print(bytes.base64EncodedString())

    return privateKey!
}

func loadSecureEnclaveKey(tag: Data) -> SecKey? {
    var item: CFTypeRef?
    var key: SecKey

    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                                kSecReturnRef as String: true]

    let status = SecItemCopyMatching(query as CFDictionary, &item)
    if status == errSecSuccess {
        key = (item as! SecKey)
        return key
    } else {
        return nil
    }
}

func deleteSecureEnclaveKey(tag: Data) -> Bool {
    let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                kSecAttrApplicationTag as String: tag,
                                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                                kSecReturnRef as String: true]

    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess
}

func loadCertificateForTagIntoTokenConfig(certificatePath: URL, tag: Data, tokenConfig: TKToken.Configuration) -> SecCertificate? {

    if FileManager.default.fileExists(atPath: certificatePath.path) {
        do {
            let certificateData = try Data(contentsOf: certificatePath)
            print("Read certificate")

            let certificate = SecCertificateCreateWithData(nil, certificateData as CFData)!
            print(certificate)

            let certificatePublicKey = SecCertificateCopyKey(certificate)

            let secKey = loadSecureEnclaveKey(tag: tag)!
            let publicKey = SecKeyCopyPublicKey(secKey)

            var error: Unmanaged<CFError>?
            let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
            let bytes: Data = ixy! as Data

            let ixy2 = SecKeyCopyExternalRepresentation(certificatePublicKey!, &error)
            let bytes2: Data = ixy2! as Data

            if bytes != bytes2 {
                print("Public key bytes of certificate do not match that of key for this tag")
                throw NSError()
            }

            let publicKeyHash = Insecure.SHA1.hash(data: bytes)

            var commonName: CFString?
            _ = SecCertificateCopyCommonName(certificate, &commonName)

            let tokenCertificate = TKTokenKeychainCertificate(certificate: certificate, objectID: tag)
            tokenCertificate?.label = "Certificate for PIV Authentication (\(commonName ?? "Secure Enclave" as CFString))"

            let tokenKey = TKTokenKeychainKey(certificate: certificate, objectID: tag)
            tokenKey?.label = "PIV AUTH key"
            tokenKey?.canSign = true
            tokenKey?.canPerformKeyExchange = true
            tokenKey?.isSuitableForLogin = true
            tokenKey?.canDecrypt = false
            tokenKey?.applicationTag = tag
            tokenKey?.keySizeInBits = 256
            tokenKey?.keyType = kSecAttrKeyTypeECSECPrimeRandom as String
            tokenKey?.publicKeyData = bytes
            tokenKey?.publicKeyHash = publicKeyHash.data

            tokenConfig.keychainItems.append(tokenKey!)
            tokenConfig.keychainItems.append(tokenCertificate!)
            return certificate
        } catch {
            print("Failed to create cert??")
        }
    } else {
        print("Certificate is not a file")
    }
    return nil
}

func importCertificateAndCreateSecIdentity(key: SecKey, certificatePath: URL, tag: Data) -> SecIdentity? {
    print("Loading certificate from \(certificatePath.path)")

    do {
        let certificateData = try Data(contentsOf: certificatePath)
        let certificate = SecCertificateCreateWithData(nil, certificateData as CFData)

        if certificate != nil {
            print("Loaded certificate \(certificate.debugDescription)")
        }

        var identity: SecIdentity?
        var status = SecIdentityCreateWithCertificate(nil, certificate!, &identity)

        if status != errSecSuccess {
            print("Failed to create identity")
        } else {
            print("Got identity: \(identity.debugDescription)")

            var item: CFTypeRef?

            let label = "Secure Enclave Generated Key".data(using: .utf8)!

            let query: [String: Any] = [
                kSecClass as String: kSecClassIdentity,
                kSecValueRef as String: identity!,
                kSecAttrApplicationTag as String: tag,
                kSecAttrLabel as String: label
            ]

            print("Adding identity to KeyChain")
            status = SecItemAdd(query as CFDictionary, &item)
            if status == errSecSuccess {
                print("Saved identity to KeyChain")
            } else {
                print("Failed to save identity: \(status)")
            }

            return identity

        }

    } catch {
        print("Failed to load certificate from \(certificatePath.path)")
    }

    return nil
}
