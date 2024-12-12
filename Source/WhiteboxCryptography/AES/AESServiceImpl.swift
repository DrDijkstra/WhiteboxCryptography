//
//  AESService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//

import Foundation

class AESServiceImpl: AESService {

    private var aes128: AES128
    private var ivBytes: [UInt8] = []

    // Initialize with a key and IV as strings
    init(key: String, iv: String) throws {
        // Validate the key and IV lengths
        guard key.count == 16 else {
            throw PreconditionError.keyLength
        }
        guard iv.count == 16 else {
            throw PreconditionError.ivLength
        }
        
        // Convert the key and IV strings to [UInt8]
        let keyBytes = key.utf8.map { UInt8($0) }
        self.ivBytes = iv.utf8.map { UInt8($0) }
        
        // Initialize AES128 with the key
        self.aes128 = AES128(key: keyBytes)
    }

    // Encrypt the block of data using AES128's encrypt method
    func encrypt(block: Data) -> Data? {
        let blockArray = [UInt8](block) // Convert Data to [UInt8]
        
        // Encrypt using AES128
        let encryptedBlock = aes128.encryptData(data: blockArray, iv: ivBytes)
        
        return encryptedBlock.isEmpty ? nil : Data(encryptedBlock) // Return encrypted data
    }

    // Decrypt the block of data using AES128's decrypt method
    func decrypt(block: Data) -> Data? {
        let blockArray = [UInt8](block) // Convert Data to [UInt8]
        
        // Decrypt using AES128
        let decryptedBlock = aes128.decryptData(data: blockArray, iv: ivBytes)
        
        return decryptedBlock.isEmpty ? nil : Data(decryptedBlock) // Return decrypted data
    }
}
