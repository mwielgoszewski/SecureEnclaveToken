//
//  TokenDriver.swift
//  SecureEnclaveTokenExtension
//
//  Created by Marcin Wielgoszewski on 2/11/21.
//

import CryptoTokenKit

class TokenDriver: TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {

    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        NSLog("CTK/SecureEnclaveTokenExtension Initializing")
        let smartCard = TKSmartCard()
        return try Token(smartCard: smartCard, tokenDriver: self, configuration: configuration)
    }

    func tokenDriver(_ driver: TKSmartCardTokenDriver, createTokenFor smartCard: TKSmartCard, aid AID: Data?) throws -> TKSmartCardToken {
        return try Token(smartCard: smartCard, aid: AID, tokenDriver: self)
    }

}
