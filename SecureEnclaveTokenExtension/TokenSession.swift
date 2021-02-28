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
        let tag = String(data: keyObjectID as! Data, encoding: .utf8)!

        NSLog("Querying for keyObjectID: \(tag) to determine whether TKTokenOperation:\(operation.rawValue) is supported")

        var item: CFTypeRef?
        var privateKey: SecKey
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                    kSecReturnRef as String: true]

        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            NSLog("Could not find private key with tag: \(tag)")
            return false
        }

        privateKey = (item as! SecKey)

        guard let alg = tokenAlgorithmToSecKeyAlgorithm(algorithm) else {
            return false
        }

        switch operation {
        case .signData:
            NSLog("Checking if keyObjectID: \(tag) can sign for algorithm \(alg.rawValue)")
            return SecKeyIsAlgorithmSupported(privateKey, SecKeyOperationType.sign, alg)
        case .performKeyExchange:
            NSLog("Checking if keyObjectID: \(tag) can perform key exchange \(alg.rawValue)")
            return SecKeyIsAlgorithmSupported(privateKey, SecKeyOperationType.keyExchange, alg)
        case .none:
            break
        case .readData:
            break
        case .decryptData:
            NSLog("Checking if keyObjectID: \(tag) can decrypt for algorithm \(alg.rawValue)")
            return SecKeyIsAlgorithmSupported(privateKey, SecKeyOperationType.decrypt, alg)
        @unknown default:
            NSLog("Unhandled token operation requested: \(operation.rawValue)")
        }

        NSLog("Key \(tag) does not support operation: \(operation.rawValue)")
        return false
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        let tag = String(data: keyObjectID as! Data, encoding: .utf8)!

        guard let alg = tokenAlgorithmToSecKeyAlgorithm(algorithm) else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.badParameter.rawValue, userInfo: nil)
        }

        NSLog("Querying for keyObjectID: \(tag) to sign \(dataToSign) with \(alg.rawValue)")

        var item: CFTypeRef?
        var privateKey: SecKey
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                    kSecReturnRef as String: true]

        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            // If the operation failed for some reason, fill in an appropriate error like objectNotFound, corruptedData, etc.
            // Note that responding with TKErrorCodeAuthenticationNeeded will trigger user authentication after which the current operation will be re-attempted.
            throw NSError(domain: TKErrorDomain, code: TKError.Code.objectNotFound.rawValue, userInfo: nil)
        }

        privateKey = (item as! SecKey)

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey,
                                                    alg,
                                                    dataToSign as CFData,
                                                    &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        return signature
    }

    func tokenSession(_ session: TKTokenSession, decrypt ciphertext: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        throw NSError(domain: TKErrorDomain, code: TKError.Code.notImplemented.rawValue, userInfo: nil)
    }

    func tokenSession(_ session: TKTokenSession, performKeyExchange otherPartyPublicKeyData: Data, keyObjectID objectID: Any, algorithm: TKTokenKeyAlgorithm, parameters: TKTokenKeyExchangeParameters) throws -> Data {

        let tag = String(data: objectID as! Data, encoding: .utf8)!

        NSLog("Querying for keyObjectID: \(tag) to perform key exchange")

        var item: CFTypeRef?
        var privateKey: SecKey
        let query: [String: Any] = [kSecClass as String: kSecClassKey,
                                    kSecAttrApplicationTag as String: tag,
                                    kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                    kSecReturnRef as String: true]

        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            // If the operation failed for some reason, fill in an appropriate error like objectNotFound, corruptedData, etc.
            // Note that responding with TKErrorCodeAuthenticationNeeded will trigger user authentication after which the current operation will be re-attempted.
            throw NSError(domain: TKErrorDomain, code: TKError.Code.objectNotFound.rawValue, userInfo: nil)
        }

        privateKey = (item as! SecKey)

        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                         kSecAttrKeySizeInBits as String: 256]

        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(otherPartyPublicKeyData as CFData,
                                                   attributes as CFDictionary,
                                                   &error) else {
            throw error!.takeRetainedValue() as Error
        }

        guard let kexAlg = tokenAlgorithmToSecKeyAlgorithm(algorithm) else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.badParameter.rawValue, userInfo: nil)
        }

        guard let secret = SecKeyCopyKeyExchangeResult(privateKey,
                                                       kexAlg,
                                                       publicKey,
                                                       parameters as! CFDictionary,
                                                       &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return secret
    }

    private func tokenAlgorithmToSecKeyAlgorithm(_ algorithm: TKTokenKeyAlgorithm) -> SecKeyAlgorithm? {

        if algorithm.isAlgorithm(.ecdsaSignatureRFC4754) {
            return .ecdsaSignatureRFC4754
        } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962) {
            return .ecdsaSignatureDigestX962
        } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA1) {
            return .ecdsaSignatureDigestX962SHA1
        } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA224) {
            return .ecdsaSignatureDigestX962SHA224
        } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA256) {
            return .ecdsaSignatureDigestX962SHA256
        } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA384) {
            return .ecdsaSignatureDigestX962SHA384
        } else if algorithm.isAlgorithm(.ecdsaSignatureDigestX962SHA512) {
            return .ecdsaSignatureDigestX962SHA512
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeStandard) {
            return .ecdhKeyExchangeStandard
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeStandardX963SHA1) {
            return .ecdhKeyExchangeStandardX963SHA1
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeStandardX963SHA224) {
            return .ecdhKeyExchangeStandardX963SHA224
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeStandardX963SHA256) {
            return .ecdhKeyExchangeStandardX963SHA256
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeStandardX963SHA384) {
            return .ecdhKeyExchangeStandardX963SHA384
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeStandardX963SHA512) {
            return .ecdhKeyExchangeStandardX963SHA512
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeCofactor) {
            return .ecdhKeyExchangeCofactor
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeCofactorX963SHA1) {
            return .ecdhKeyExchangeCofactorX963SHA1
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeCofactorX963SHA224) {
            return .ecdhKeyExchangeCofactorX963SHA224
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeCofactorX963SHA256) {
            return .ecdhKeyExchangeCofactorX963SHA256
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeCofactorX963SHA384) {
            return .ecdhKeyExchangeCofactorX963SHA384
        } else if algorithm.isAlgorithm(.ecdhKeyExchangeCofactorX963SHA512) {
            return .ecdhKeyExchangeCofactorX963SHA512
        }

        return nil

    }

}
