//
//  AESCoreTests.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import XCTest

class AESCoreTests: XCTestCase {

    // Test case for ECB mode with all key sizes (128, 192, 256 bits)
    func testECBEncryptionDecryption() {
        let plaintext: [UInt8] = Array("Hello, AES ECB!".utf8)
        
        for keySize in [16, 24, 32] {  // Key sizes in bytes for 128, 192, and 256 bits
            let key: [UInt8] = Array(repeating: 0x2b, count: keySize)  // Example key, with all bits set to 0x2b
            
            do {
                let aes = try AESCore(key: key, mode: .ecb)
                
                // Encrypt
                let encryptedData = try aes.encryptData(data: plaintext)
                XCTAssertFalse(encryptedData.isEmpty, "Encrypted data should not be empty for key size \(keySize * 8)-bit")
                
                // Decrypt
                let decryptedData = (try aes.decryptData(data: encryptedData))!
                let decryptedText = String(bytes: decryptedData, encoding: .utf8)
                
                XCTAssertEqual(decryptedText, "Hello, AES ECB!", "Decrypted data should match the original plaintext for key size \(keySize * 8)-bit")
            } catch {
                XCTFail("Encryption/Decryption failed with error for key size \(keySize * 8)-bit: \(error)")
            }
        }
    }

    // Test case for CBC mode with all key sizes (128, 192, 256 bits)
    func testCBCEncryptionDecryption() {
        let iv: [UInt8] = Array(repeating: 0x01, count: 16)  // Example IV (16 bytes)
        let plaintext: [UInt8] = Array("Hello, AES CBC!".utf8)
        
        for keySize in [16, 24, 32] {  // Key sizes in bytes for 128, 192, and 256 bits
            let key: [UInt8] = Array(repeating: 0x2b, count: keySize)
            
            do {
                let aes = try AESCore(key: key, mode: .cbc)
                
                // Encrypt
                let encryptedData = try aes.encryptData(data: plaintext, iv: iv)
                XCTAssertFalse(encryptedData.isEmpty, "Encrypted data should not be empty for key size \(keySize * 8)-bit")
                
                // Decrypt
                let decryptedData = try aes.decryptData(data: encryptedData, iv: iv)
                let decryptedText = String(bytes: decryptedData!, encoding: .utf8)
                
                XCTAssertEqual(decryptedText, "Hello, AES CBC!", "Decrypted data should match the original plaintext for key size \(keySize * 8)-bit")
            } catch {
                XCTFail("Encryption/Decryption failed with error for key size \(keySize * 8)-bit: \(error)")
            }
        }
    }

    // Test case for GCM mode with all key sizes (128, 192, 256 bits)
    func testGCMEncryptionDecryption() {
        let iv: [UInt8] = Array(repeating: 0x01, count: 12)  // Example IV (12 bytes for GCM)
        let plaintext: [UInt8] = Array("Hello, AES GCM!".utf8)
        
        for keySize in [16, 24, 32] {  // Key sizes in bytes for 128, 192, and 256 bits
            let key: [UInt8] = Array(repeating: 0x2b, count: keySize)
            
            do {
                let aes = try AESCore(key: key, mode: .gcm)
                
                // Encrypt
                let encryptedData = try aes.encryptData(data: plaintext, iv: iv)
                XCTAssertFalse(encryptedData.isEmpty, "Encrypted data should not be empty for key size \(keySize * 8)-bit")
                
                // Decrypt
                let decryptedData = try aes.decryptData(data: encryptedData, iv: iv)
                let decryptedText = String(bytes: decryptedData!, encoding: .utf8)
                
                XCTAssertEqual(decryptedText, "Hello, AES GCM!", "Decrypted data should match the original plaintext for key size \(keySize * 8)-bit")
            } catch {
                XCTFail("Encryption/Decryption failed with error for key size \(keySize * 8)-bit: \(error)")
            }
        }
    }
}
