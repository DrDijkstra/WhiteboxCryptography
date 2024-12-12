//
//  AESService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//

import Foundation

class AESServiceImpl: AESService {

    private var aes: AESCore
    private var ivBytes: [UInt8] = []

    // Initialize with a key and IV as strings
    init(key: String, iv: String) throws {
        
        // Convert the key and IV strings to [UInt8]
        let keyBytes = key.utf8.map { UInt8($0) }
        self.ivBytes = iv.utf8.map { UInt8($0) }
        
        // Initialize AES128 with the key
        self.aes = AESCore(key: keyBytes)
    }

    // Encrypt the block of data using AES128's encrypt method
    func encrypt(block: Data) -> Data? {
        let blockArray = [UInt8](block) // Convert Data to [UInt8]
        
        // Encrypt using AES128
        let encryptedBlock = aes.encryptData(data: blockArray, iv: ivBytes)
        
        return encryptedBlock.isEmpty ? nil : Data(encryptedBlock) // Return encrypted data
    }

    // Decrypt the block of data using AES128's decrypt method
    func decrypt(block: Data) -> Data? {
        let blockArray = [UInt8](block) // Convert Data to [UInt8]
        
        // Decrypt using AES128
        let decryptedBlock = aes.decryptData(data: blockArray, iv: ivBytes)
        
        return decryptedBlock.isEmpty ? nil : Data(decryptedBlock) // Return decrypted data
    }
}
