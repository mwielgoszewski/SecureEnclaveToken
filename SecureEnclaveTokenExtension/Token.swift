import CryptoTokenKit

final class Token: TKToken, TKTokenDelegate {
    init(tokenDriver: TokenDriver, instanceID: TKToken.InstanceID) {
        super.init(tokenDriver: tokenDriver, instanceID: instanceID)
        delegate = self
        keychainContents?.fill(with: configuration.keychainItems)
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        TokenSession(token: self)
    }
}
