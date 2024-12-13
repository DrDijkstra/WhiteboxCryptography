//
//  AESService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//

import Foundation

public class AESServiceImpl: AESService {
    
    private var aes: AESCore
    
    public init() {
        aes = AESCore()
    }
    
    public func encrypt(block: Data, key: Data, iv: Data?, mode: AESMode) throws -> Data? {
        let blockBytes = [UInt8](block)
        let keyBytes = [UInt8](key)
        let ivBytes = iv != nil ? [UInt8](iv!) : []

        try aes.update(key: keyBytes, mode: mode)

        let encryptedBytes = try aes.encryptData(data: blockBytes, iv: ivBytes)

        return Data(encryptedBytes)
    }

    public func decrypt(block: Data, key: Data, iv: Data?, mode: AESMode) throws -> Data? {
        let blockBytes = [UInt8](block)
        let keyBytes = [UInt8](key)
        let ivBytes = iv != nil ? [UInt8](iv!) : []

        try aes.update(key: keyBytes, mode: mode)
        guard let decryptedBytes = try aes.decryptData(data: blockBytes, iv: ivBytes) else{
            throw CryptographicError.decryptionError
        }

        return Data(decryptedBytes)
    }
}
