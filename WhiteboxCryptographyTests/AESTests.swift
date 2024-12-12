//
//  AESTests.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import XCTest

class AESTests: XCTestCase {
    
    var aes: AESCore!
    var iv: [UInt8]!
    
    override func setUp() {
        super.setUp()
        iv = [UInt8](repeating: 0x00, count: 16)  // 16 bytes IV for CBC mode
    }

    override func tearDown() {
        aes = nil
        iv = nil
        super.tearDown()
    }

    // Test AES-128 (16 bytes key)
    func testEncryptionDecryptionAES128() {
        let key: [UInt8] = [UInt8](repeating: 0x2b, count: 16)  // 128-bit key (16 bytes)
        aes = AESCore(key: key)
        
        let plaintext: [UInt8] = Array("AES-128 test message.".utf8)
        
        // Encrypt the data
        let encryptedData = aes.encryptData(data: plaintext, iv: iv)
        
        // Decrypt the data
        let decryptedData = aes.decryptData(data: encryptedData, iv: iv)
        
        // Convert decrypted data back to a string
        let decryptedString = String(bytes: decryptedData, encoding: .utf8)
        
        // Check if the decrypted string matches the original plaintext
        XCTAssertEqual(decryptedString, "AES-128 test message.")
    }

    // Test AES-192 (24 bytes key)
    func testEncryptionDecryptionAES192() {
        let key: [UInt8] = [UInt8](repeating: 0x2b, count: 24)  // 192-bit key (24 bytes)
        aes = AESCore(key: key)
        
        let plaintext: [UInt8] = Array("AES-192 test message.".utf8)
        
        // Encrypt the data
        let encryptedData = aes.encryptData(data: plaintext, iv: iv)
        
        // Decrypt the data
        let decryptedData = aes.decryptData(data: encryptedData, iv: iv)
        
        // Convert decrypted data back to a string
        let decryptedString = String(bytes: decryptedData, encoding: .utf8)
        
        // Check if the decrypted string matches the original plaintext
        XCTAssertEqual(decryptedString, "AES-192 test message.")
    }

    // Test AES-256 (32 bytes key)
    func testEncryptionDecryptionAES256() {
        let key: [UInt8] = [UInt8](repeating: 0x2b, count: 32)  // 256-bit key (32 bytes)
        aes = AESCore(key: key)
        
        let plaintext: [UInt8] = Array("AES-256 test message.".utf8)
        
        // Encrypt the data
        let encryptedData = aes.encryptData(data: plaintext, iv: iv)
        
        // Decrypt the data
        let decryptedData = aes.decryptData(data: encryptedData, iv: iv)
        
        // Convert decrypted data back to a string
        let decryptedString = String(bytes: decryptedData, encoding: .utf8)
        
        // Check if the decrypted string matches the original plaintext
        XCTAssertEqual(decryptedString, "AES-256 test message.")
    }
}
