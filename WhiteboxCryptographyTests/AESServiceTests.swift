//
//  AESServiceTests 2.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import XCTest

class AESServiceTests: XCTestCase {

    // Example key and IV as strings
    let key: String = "1234567890abcdef" // 16 characters (128-bit key)
    let iv: String = "abcdef1234567890"  // 16 characters (128-bit IV)

    var aesService: AESServiceImpl!

    override func setUp() {
        super.setUp()
        // Initialize AESServiceImpl with string key and IV
        do{
            aesService = try AESServiceImpl(key: key, iv: iv)
        }catch{
            
        }
    }

    override func tearDown() {
        aesService = nil
        super.tearDown()
    }

    func testEncryption() {
        // Test that encryption produces non-nil, different data
        let plaintext = "Hello, AES!"
        let dataToEncrypt = plaintext.data(using: .utf8)!
        
        // Encrypt the data
        if let encryptedData = aesService.encrypt(block: dataToEncrypt) {
            XCTAssertNotNil(encryptedData, "Encrypted data should not be nil")
            XCTAssertNotEqual(encryptedData, dataToEncrypt, "Encrypted data should not be the same as the plaintext")
        } else {
            XCTFail("Encryption failed")
        }
    }

    func testDecryption() {
        // Test that decryption returns the original plaintext
        let plaintext = "Hello, AES!"
        let dataToEncrypt = plaintext.data(using: .utf8)!
        
        // Encrypt the data
        if let encryptedData = aesService.encrypt(block: dataToEncrypt) {
            XCTAssertNotNil(encryptedData, "Encrypted data should not be nil")
            
            // Decrypt the data back
            if let decryptedData = aesService.decrypt(block: encryptedData) {
                XCTAssertNotNil(decryptedData, "Decrypted data should not be nil")
                let decryptedString = String(data: decryptedData, encoding: .utf8)
                XCTAssertEqual(decryptedString, plaintext, "Decrypted text should match the original plaintext")
            } else {
                XCTFail("Decryption failed")
            }
        } else {
            XCTFail("Encryption failed")
        }
    }

    func testEncryptionDecryptionSymmetry() {
        // Test encryption and decryption symmetry (round-trip)
        let plaintext = "Hello, AES!"
        let dataToEncrypt = plaintext.data(using: .utf8)!
        
        // Encrypt the data
        if let encryptedData = aesService.encrypt(block: dataToEncrypt) {
            // Decrypt the data back
            print("encryptedString \(encryptedData.toBase64String())")

            if let decryptedData = aesService.decrypt(block: encryptedData) {
                let decryptedString = String(data: decryptedData, encoding: .utf8)
                
                XCTAssertEqual(decryptedString, plaintext, "Decrypted text should match the original plaintext")
            } else {
                XCTFail("Decryption failed")
            }
        } else {
            XCTFail("Encryption failed")
        }
    }

    // Test invalid key length (less than 16 characters)
    func testInvalidKeyLength() {
        let invalidKey = "12345"  // Invalid key (less than 16 characters)
        let validIV = "1234567890abcdef"  // Valid IV
        
        // Expecting an error due to invalid key length
        XCTAssertThrowsError(try AESServiceImpl(key: invalidKey, iv: validIV)) { error in
            XCTAssertEqual(error as? PreconditionError, PreconditionError.keyLength)
        }
    }

    // Test invalid IV length (less than 16 characters)
    func testInvalidIVLength() {
        let validKey = "1234567890abcdef"  // Valid key
        let invalidIV = "12345"  // Invalid IV (less than 16 characters)
        
        // Expecting an error due to invalid IV length
        XCTAssertThrowsError(try AESServiceImpl(key: validKey, iv: invalidIV)) { error in
            XCTAssertEqual(error as? PreconditionError, PreconditionError.ivLength)
        }
    }

    // Test valid key and IV length
    func testValidKeyAndIVLength() {
        let validKey = "1234567890abcdef"  // Valid key (16 characters)
        let validIV = "1234567890abcdef"  // Valid IV (16 characters)
        
        // Should not throw any error
        XCTAssertNoThrow(try AESServiceImpl(key: validKey, iv: validIV))
    }
}
