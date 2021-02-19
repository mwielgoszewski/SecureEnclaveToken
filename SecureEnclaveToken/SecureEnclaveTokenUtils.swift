//
//  SecureEnclaveTokenUtils.swift
//  SecureEnclaveToken
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import Foundation
import Security
import CryptoTokenKit


func generateKeyInEnclave(tag: Data, accessibility: CFString, accessControlFlags: Int) -> SecKey {
    print("Generating key ...")
    
    var flags: SecAccessControlCreateFlags
    
    switch accessControlFlags {
    case 1:
        flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.userPresence]
        break
    case 2:
        flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.devicePasscode]
        break
    case 3:
        flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.biometryAny]
        break
    default:
        flags = [SecAccessControlCreateFlags.privateKeyUsage]
    }

    let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                 accessibility,
                                                 flags,
                                                 nil)! // ignore error
        
    let attributes: [String: Any] = [
      kSecAttrKeyType as String:            kSecAttrKeyTypeEC,
      kSecAttrKeySizeInBits as String:      256,
      kSecAttrTokenID as String:            kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String:      true,
        kSecAttrApplicationTag as String:   tag,
        kSecAttrAccessControl as String:    access
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
    print("Signature: \(signature)")
    
    let ixy = SecKeyCopyExternalRepresentation(publicKey!, &error)
    print(ixy!)
    
    let bytes:Data = ixy! as Data
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


func loadCertificateForTagIntoTokenConfig(certificatePath: URL, tag: Data, tokenConfig: TKToken.Configuration) -> Bool {

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
            let bytes:Data = ixy! as Data
            
            let ixy2 = SecKeyCopyExternalRepresentation(certificatePublicKey!, &error)
            let bytes2:Data = ixy2! as Data

            if bytes != bytes2 {
                print("Public key bytes of certificate do not match that of key for this tag")
                throw NSError()
            }
            
            let tokenCertificate = TKTokenKeychainCertificate(certificate: certificate, objectID: tag)
            tokenCertificate?.label = "se certificate"

            let tokenKey = TKTokenKeychainKey(certificate: certificate, objectID: tag)
            tokenKey?.label = "se key"
            tokenKey?.canSign = true
            tokenKey?.canPerformKeyExchange = true
            tokenKey?.isSuitableForLogin = true
            tokenKey?.canDecrypt = false
            
            tokenConfig.keychainItems.append(tokenKey!)
            tokenConfig.keychainItems.append(tokenCertificate!)
            return true
        } catch {
            print("Failed to create cert??")
            return false
        }
    } else {
        print("Certificate is not a file")
    }
    return false
}

func signCertRequestTbsData(key: SecKey, contentsOf: URL, outputSignature: URL) -> Bool {
    print("Reading certificate request \(contentsOf.path)")
    
    do {
        let tbsCertRequestBytes = try Data(contentsOf: contentsOf)
        
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(key,
                                              .ecdsaSignatureMessageX962SHA256,
                                              tbsCertRequestBytes as CFData,
                                              &error) as Data?
        
        print(error)
        print(signature!)
        
        do {
            try signature?.write(to: outputSignature)
            print("Signed tbs to \(outputSignature.path)")
            return true
        } catch {
            print("Failed writing signature")
        }

    } catch {
        print("Failed reading certificate request")
    }
    return false
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
                kSecAttrApplicationTag as String:   tag,
                kSecAttrLabel as String:            label,
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
