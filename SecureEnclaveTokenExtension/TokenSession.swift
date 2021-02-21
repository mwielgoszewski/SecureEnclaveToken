//
//  TokenSession.swift
//  SecureEnclaveTokenExtension
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import CryptoTokenKit

class TokenSession: TKSmartCardTokenSession, TKTokenSessionDelegate {

    func tokenSession(_ session: TKTokenSession, beginAuthFor operation: TKTokenOperation, constraint: Any) throws -> TKTokenAuthOperation {
        // Insert code here to create an instance of TKTokenAuthOperation based on the specified operation and constraint.
        // Note that the constraint was previously established when populating keychainContents during token initialization.
        return TKTokenSmartCardPINAuthOperation()
    }

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) -> Bool {
        // Indicate whether the given key supports the specified operation and algorithm.
        NSLog("Determining if \(keyObjectID) supports \(operation.rawValue)")
        do {
            let tokenKey = try self.token.keychainContents?.key(forObjectID: keyObjectID)

            switch operation {
            case .signData:
                NSLog("Checking if key can sign for algorithm \(algorithm)")
                if tokenKey!.canSign {
                    if algorithm.isAlgorithm(.ecdsaSignatureRFC4754) {
                        NSLog("Can sign ecdsaSignatureRFC4754")
                        return true
                    } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962) {
                        NSLog("Can sign ecdsaSignatureDigestX962")
                        return true
                    } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA1) {
                        NSLog("Can sign ecdsaSignatureDigestX962SHA1")
                        return true
                    } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA224) {
                        NSLog("Can sign ecdsaSignatureDigestX962SHA224")
                        return true
                    } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA256) {
                        NSLog("Can sign ecdsaSignatureDigestX962SHA256")
                        return true
                    } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA384) {
                        NSLog("Can sign ecdsaSignatureDigestX962SHA384")
                        return true
                    } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA512) {
                        NSLog("Can sign ecdsaSignatureDigestX962SHA512")
                        return true
                    }
                    return false
                }

            case .performKeyExchange:
                NSLog("Checking if key can perform key exchange \(algorithm)")
                if tokenKey!.canPerformKeyExchange {
                    return true
                }

            case .none:
                break
            case .readData:
                break
            case .decryptData:
                break
            @unknown default:
                NSLog("Unhandled token operation requested: \(operation.rawValue)")
            }
        } catch {
            NSLog("Could not find private key: \(keyObjectID)")
            return false
        }

        NSLog("Key \(keyObjectID) does not support operation: \(operation.rawValue)")
        return false
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        var signature: Data?
        var item: CFTypeRef?
        var privateKey: SecKey

        NSLog("Querying for key \(keyObjectID)")

        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: keyObjectID,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                    kSecReturnRef as String: true]

        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess {
            privateKey = (item as! SecKey)
            var error: Unmanaged<CFError>?
            var alg: SecKeyAlgorithm = .ecdsaSignatureDigestX962

            if algorithm.isAlgorithm(.ecdsaSignatureRFC4754) {
                alg = .ecdsaSignatureRFC4754
            } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962) {
                NSLog("Can sign ecdsaSignatureDigestX962")
                alg = .ecdsaSignatureDigestX962
            } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA1) {
                NSLog("Can sign ecdsaSignatureDigestX962SHA1")
                alg = .ecdsaSignatureDigestX962SHA1
            } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA224) {
                NSLog("Can sign ecdsaSignatureDigestX962SHA224")
                alg = .ecdsaSignatureDigestX962SHA224
            } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA256) {
                NSLog("Can sign ecdsaSignatureDigestX962SHA256")
                alg = .ecdsaSignatureDigestX962SHA256
            } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA384) {
                NSLog("Can sign ecdsaSignatureDigestX962SHA384")
                alg = .ecdsaSignatureDigestX962SHA384
            } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA512) {
                NSLog("Can sign ecdsaSignatureDigestX962SHA512")
                alg = .ecdsaSignatureDigestX962SHA512
            }

            signature = SecKeyCreateSignature(privateKey,
                                              alg,
                                              dataToSign as CFData,
                                              &error) as Data?
            return signature!
        } else {
            // If the operation failed for some reason, fill in an appropriate error like objectNotFound, corruptedData, etc.
            // Note that responding with TKErrorCodeAuthenticationNeeded will trigger user authentication after which the current operation will be re-attempted.
            throw NSError(domain: TKErrorDomain, code: TKError.Code.objectNotFound.rawValue, userInfo: nil)
        }
    }

    func tokenSession(_ session: TKTokenSession, decrypt ciphertext: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        throw NSError(domain: TKErrorDomain, code: TKError.Code.notImplemented.rawValue, userInfo: nil)
    }

    func tokenSession(_ session: TKTokenSession, performKeyExchange otherPartyPublicKeyData: Data, keyObjectID objectID: Any, algorithm: TKTokenKeyAlgorithm, parameters: TKTokenKeyExchangeParameters) throws -> Data {
        var secret: Data?

        var item: CFTypeRef?
        var privateKey: SecKey

        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: objectID,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                    kSecReturnRef as String: true]

        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecSuccess {
            privateKey = (item as! SecKey)
            var error: Unmanaged<CFError>?

            let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                             kSecAttrKeySizeInBits as String: 256]

            let publicKey = SecKeyCreateWithData(otherPartyPublicKeyData as CFData, attributes as CFDictionary, &error)!

            secret = SecKeyCopyKeyExchangeResult(privateKey, SecKeyAlgorithm.ecdhKeyExchangeStandard, publicKey, parameters as! CFDictionary, &error) as Data?
            return secret!

        } else {
            // If the operation failed for some reason, fill in an appropriate error like objectNotFound, corruptedData, etc.
            // Note that responding with TKErrorCodeAuthenticationNeeded will trigger user authentication after which the current operation will be re-attempted.
            throw NSError(domain: TKErrorDomain, code: TKError.Code.badParameter.rawValue, userInfo: nil)
        }
    }
}
