//
//  AESService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//

import Foundation

class AESServiceImpl: AESService {
    
    private var aes: AESCore
    
    init() {
        aes = AESCore()
    }
    
    func encrypt(block: Data, key: Data, iv: Data?, mode: AESMode) throws -> Data? {
        let blockBytes = [UInt8](block)
        let keyBytes = [UInt8](key)
        let ivBytes = iv != nil ? [UInt8](iv!) : []

        try aes.update(key: keyBytes, mode: mode)

        let encryptedBytes = try aes.encryptData(data: blockBytes, iv: ivBytes)

        return Data(encryptedBytes)
    }

    func decrypt(block: Data, key: Data, iv: Data?, mode: AESMode) throws -> Data? {
        let blockBytes = [UInt8](block)
        let keyBytes = [UInt8](key)
        let ivBytes = iv != nil ? [UInt8](iv!) : []

        try aes.update(key: keyBytes, mode: mode)
        guard let decryptedBytes = try aes.decryptData(data: blockBytes, iv: ivBytes) else{
            throw AESCoreError.decryptionError
        }

        return Data(decryptedBytes)
    }
}
