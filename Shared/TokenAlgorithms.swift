import CryptoTokenKit
import Security

// Keep advertised algorithms consistent with the implemented operations.
enum TokenAlgorithms {
    static func resolve(_ algorithm: TKTokenKeyAlgorithm, operation: TKTokenOperation) -> SecKeyAlgorithm? {
        let candidates: [SecKeyAlgorithm]
        switch operation {
        case .signData:
            candidates = [
                .ecdsaSignatureDigestRFC4754, .ecdsaSignatureDigestX962,
                .ecdsaSignatureDigestX962SHA1, .ecdsaSignatureDigestX962SHA224,
                .ecdsaSignatureDigestX962SHA256, .ecdsaSignatureDigestX962SHA384,
                .ecdsaSignatureDigestX962SHA512
            ]
        case .performKeyExchange:
            candidates = [
                .ecdhKeyExchangeStandard, .ecdhKeyExchangeStandardX963SHA1,
                .ecdhKeyExchangeStandardX963SHA224, .ecdhKeyExchangeStandardX963SHA256,
                .ecdhKeyExchangeStandardX963SHA384, .ecdhKeyExchangeStandardX963SHA512,
                .ecdhKeyExchangeCofactor, .ecdhKeyExchangeCofactorX963SHA1,
                .ecdhKeyExchangeCofactorX963SHA224, .ecdhKeyExchangeCofactorX963SHA256,
                .ecdhKeyExchangeCofactorX963SHA384, .ecdhKeyExchangeCofactorX963SHA512
            ]
        default: return nil
        }
        return candidates.first { algorithm.isAlgorithm($0) }
    }

    static func exchangeParameters(requestedSize: Int, sharedInfo: Data?) -> [String: Any] {
        var result: [String: Any] = [SecKeyKeyExchangeParameter.requestedSize.rawValue as String: requestedSize]
        if let sharedInfo { result[SecKeyKeyExchangeParameter.sharedInfo.rawValue as String] = sharedInfo }
        return result
    }

    @discardableResult
    static func validateObjectID(_ objectID: Any) throws -> Data {
        guard let tag = objectID as? Data, !tag.isEmpty else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.objectNotFound.rawValue)
        }
        return tag
    }
}
