import CryptoTokenKit
import Security

final class TokenSession: TKTokenSession, TKTokenSessionDelegate {
    override init(token: TKToken) {
        super.init(token: token)
        delegate = self
    }

    // Authentication is enforced by the SecKey's access control, including Touch ID.
    // There is no independent smart-card PIN or PIN authentication operation.
    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation,
                      keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) -> Bool {
        guard let resolved = TokenAlgorithms.resolve(algorithm, operation: operation),
              let key = try? privateKey(for: keyObjectID) else { return false }
        switch operation {
        case .signData: return SecKeyIsAlgorithmSupported(key, .sign, resolved)
        case .performKeyExchange: return SecKeyIsAlgorithmSupported(key, .keyExchange, resolved)
        default: return false
        }
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data,
                      keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        let key = try privateKey(for: keyObjectID)
        guard let resolved = TokenAlgorithms.resolve(algorithm, operation: .signData),
              SecKeyIsAlgorithmSupported(key, .sign, resolved) else { throw unsupportedAlgorithm() }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, resolved, dataToSign as CFData, &error) else {
            throw TokenFailure.underlying(error, fallback: "The signing operation failed.")
        }
        return signature as Data
    }

    func tokenSession(_ session: TKTokenSession, performKeyExchange otherPartyPublicKeyData: Data,
                      keyObjectID: Any, algorithm: TKTokenKeyAlgorithm,
                      parameters: TKTokenKeyExchangeParameters) throws -> Data {
        let key = try privateKey(for: keyObjectID)
        guard let resolved = TokenAlgorithms.resolve(algorithm, operation: .performKeyExchange),
              SecKeyIsAlgorithmSupported(key, .keyExchange, resolved) else { throw unsupportedAlgorithm() }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let peerKey = SecKeyCreateWithData(otherPartyPublicKeyData as CFData, attributes as CFDictionary, &error) else {
            throw TokenFailure.underlying(error, fallback: "The peer public key is invalid.")
        }
        let exchangeParameters = TokenAlgorithms.exchangeParameters(
            requestedSize: parameters.requestedSize, sharedInfo: parameters.sharedInfo
        )
        guard let secret = SecKeyCopyKeyExchangeResult(key, resolved, peerKey, exchangeParameters as CFDictionary, &error) else {
            throw TokenFailure.underlying(error, fallback: "The key exchange failed.")
        }
        return secret as Data
    }

    private func privateKey(for objectID: Any) throws -> SecKey {
        let tag = try TokenAlgorithms.validateObjectID(objectID)
        // Check that this object is actually published by this token configuration.
        _ = try token.configuration.key(for: tag)
        return try TokenSecurity.requireKey(tag: tag)
    }

    private func unsupportedAlgorithm() -> NSError {
        NSError(domain: TKErrorDomain, code: TKError.Code.badParameter.rawValue)
    }
}
