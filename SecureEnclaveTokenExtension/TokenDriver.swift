import CryptoTokenKit

final class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
    override init() {
        super.init()
        delegate = self
    }

    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        Token(tokenDriver: self, instanceID: configuration.instanceID)
    }
}
