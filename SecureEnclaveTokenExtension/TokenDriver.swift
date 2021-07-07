//
//  TokenDriver.swift
//  SecureEnclaveTokenExtension
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import CryptoTokenKit

class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {

    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        NSLog("CTK/SecureEnclaveTokenExtension Initializing")
        return try Token(tokenDriver: self, instanceID: configuration.instanceID)
    }
}
