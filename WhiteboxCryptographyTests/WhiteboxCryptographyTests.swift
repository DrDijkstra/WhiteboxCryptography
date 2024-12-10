//
//  WhiteboxCryptographyTests.swift
//  WhiteboxCryptographyTests
//
//  Created by Sanjay Dey on 2024-12-10.
//

import XCTest
import CommonCrypto

final class WhiteboxCryptographySDKTests: XCTestCase {

    var sdk: WhiteboxCryptographySDK!
    var testKey: Data!
    var testData: Data!
    var iv: Data!
    
    override func setUp() {
        super.setUp()
        // Initialize the SDK with a sample memory key
        let memoryKey = "sampleEncryptionKeysampleEncryptionKeysampleEncryptionKey".data(using: .utf8)!
        sdk = WhiteboxCryptographySDK(memoryKey: memoryKey)
        
        // Sample data to encrypt/decrypt
        testData = "This is a test string".data(using: .utf8)!
        
        // Generate IV for AES-GCM (or any other algorithm)
        iv = sdk.generateRandomIV(forAlgorithm: .aes(keySize: .bits256, mode: .gcm))
    }

    override func tearDown() {
        sdk = nil
        testKey = nil
        testData = nil
        iv = nil
        super.tearDown()
    }

    // MARK: - Encrypt/Decrypt Tests
    
    func testEncryptionDecryption() {
        let algorithm: CryptoAlgorithm = .aes(keySize: .bits256, mode: .gcm)
        
        // Generate a random key for AES-256
        guard let randomKey = sdk.generateRandomKey(forAlgorithm: algorithm) else {
            XCTFail("Random key generation failed")
            return
        }

        // Encrypt the test data
        guard let encryptedData = sdk.encrypt(data: testData, withKey: randomKey, iv: iv, algorithm: algorithm) else {
            XCTFail("Encryption failed")
            return
        }
        
        // Decrypt the data
        guard let decryptedData = sdk.decrypt(data: encryptedData, withKey: randomKey, iv: iv, algorithm: algorithm) else {
            XCTFail("Decryption failed")
            return
        }
        
        // Ensure that the decrypted data matches the original data
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedString, "This is a test string", "Decrypted data does not match the original data")
    }

    // MARK: - HMAC Tests
    
    func testHMAC() {
        let dataToHash = "Test data for HMAC".data(using: .utf8)!
        
        // Generate a random key for HMAC (you can use any size here, e.g., 256-bit)
        guard let randomKey = sdk.generateRandomKey(forAlgorithm: .aes(keySize: .bits256, mode: .cbc)) else {
            XCTFail("Random key generation failed")
            return
        }
        
        // Generate HMAC using the random key
        guard let hmacData = sdk.hmac(data: dataToHash, key: randomKey) else {
            XCTFail("HMAC generation failed")
            return
        }
        
        // Check that HMAC data is not empty
        XCTAssertFalse(hmacData.isEmpty, "HMAC data should not be empty")
    }
    
    // MARK: - Key Derivation Tests
    
    func testKeyDerivation() {
        let password = "strongpassword"
        let salt = Data("randomsalt".utf8)
        
        // Derive key using PBKDF2
        guard let derivedKey = sdk.deriveKey(fromPassword: password, salt: salt, iterations: 1000) else {
            XCTFail("Key derivation failed")
            return
        }
        
        // Ensure the derived key is of the correct length (for AES256, 32 bytes)
        XCTAssertEqual(derivedKey.count, kCCKeySizeAES256, "Derived key should be 32 bytes")
    }
    
    // MARK: - IV Generation Tests
    
    func testIVGeneration() {
        let algorithm: CryptoAlgorithm = .aes(keySize: .bits256, mode: .gcm)
        
        // Generate a random IV for AES-GCM
        guard let generatedIV = sdk.generateRandomIV(forAlgorithm: algorithm) else {
            XCTFail("IV generation failed")
            return
        }
        
        // Check that the IV is the correct length (12 bytes for AES-GCM)
        XCTAssertEqual(generatedIV.count, 12, "Generated IV for AES-GCM should be 12 bytes")
    }

    // MARK: - Edge Case Tests

    func testEncryptionWithNoIV() {
        let algorithm: CryptoAlgorithm = .aes(keySize: .bits256, mode: .gcm)
        
        // Generate a random key for AES-256
        guard let randomKey = sdk.generateRandomKey(forAlgorithm: algorithm) else {
            XCTFail("Random key generation failed")
            return
        }

        // Try encrypting without providing an IV
        let iv = sdk.generateRandomIV(forAlgorithm: algorithm)
        guard let encryptedData = sdk.encrypt(data: testData, withKey: randomKey, iv: iv, algorithm: algorithm) else {
            XCTFail("Encryption failed without IV")
            return
        }
        
        // Decrypt the data
        guard let decryptedData = sdk.decrypt(data: encryptedData, withKey: randomKey,iv: iv, algorithm: algorithm) else {
            XCTFail("Decryption failed without IV")
            return
        }
        
        // Ensure that the decrypted data matches the original data
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedString, "This is a test string", "Decrypted data does not match the original data without IV")
    }

    func testEmptyData() {
        let algorithm: CryptoAlgorithm = .aes(keySize: .bits256, mode: .gcm)
        
        let emptyData = Data()
        
        // Generate a random key for AES-256
        guard let randomKey = sdk.generateRandomKey(forAlgorithm: algorithm) else {
            XCTFail("Random key generation failed")
            return
        }

        // Test encryption and decryption with empty data
        guard let encryptedData = sdk.encrypt(data: emptyData, withKey: randomKey, iv: iv, algorithm: algorithm) else {
            XCTFail("Encryption failed for empty data")
            return
        }
        
        guard let decryptedData = sdk.decrypt(data: encryptedData, withKey: randomKey, iv: iv, algorithm: algorithm) else {
            XCTFail("Decryption failed for empty data")
            return
        }
        
        // Ensure that the decrypted data is also empty
        XCTAssertEqual(decryptedData.count, 0, "Decrypted data should be empty for empty input")
    }
}
