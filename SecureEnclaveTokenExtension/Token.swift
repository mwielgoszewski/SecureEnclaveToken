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
        do {
            let tag = "com.mwielgoszewski.SecureEnclaveToken.Key".data(using: .utf8)!
            let certificate = try self.keychainContents?.certificate(forObjectID: tag)
            NSLog("Got certificate for \(String(describing: certificate?.label)) -> \(String(describing: certificate?.data.base64EncodedString()))")
        } catch {
            NSLog("Failed pulling certificate")
        }
        NSLog("Got keychain items: \(String(describing: self.keychainContents?.items.count))")
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        return TokenSession(token: self)
    }

}
