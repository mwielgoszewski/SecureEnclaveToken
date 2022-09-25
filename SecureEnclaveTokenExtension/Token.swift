//
//  Token.swift
//  SecureEnclaveTokenExtension
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import CryptoTokenKit

class Token: TKToken, TKTokenDelegate {

    init(tokenDriver: TokenDriver, instanceID: TKToken.InstanceID) throws {
        NSLog("Initializing Token configuration based interface")
        NSLog("Got instanceID: \(instanceID)")
        super.init(tokenDriver: tokenDriver, instanceID: instanceID)
        self.keychainContents?.fill(with: configuration.keychainItems)
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        return TokenSession(token: self)
    }

}
