//
//  Token.swift
//  SecureEnclaveTokenExtension
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import CryptoTokenKit

class Token: TKSmartCardToken, TKTokenDelegate {

    init(smartCard: TKSmartCard, tokenDriver: TokenDriver, configuration: TKToken.Configuration) throws {
        NSLog("Initializing Token configuration based interface")
        NSLog("Got instanceID: \(configuration.instanceID)")
        super.init(smartCard: smartCard, aid: nil, instanceID: configuration.instanceID, tokenDriver: tokenDriver)
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

    init(smartCard: TKSmartCard, aid AID: Data?, tokenDriver: TKSmartCardTokenDriver) throws {
        let instanceID = "token_instance_id" // Fill in a unique persistent identifier of the token instance.
        super.init(smartCard: smartCard, aid: AID, instanceID: instanceID, tokenDriver: tokenDriver)
        // Insert code here to enumerate token objects and populate keychainContents with instances of TKTokenKeychainCertificate, TKTokenKeychainKey, etc.
        let items = [TKTokenKeychainItem]()
        self.keychainContents!.fill(with: items)
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        return TokenSession(token: self)
    }

}
