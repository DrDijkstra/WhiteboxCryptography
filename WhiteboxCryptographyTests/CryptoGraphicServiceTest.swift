//
//  CryptoGraphicServiceTest.swift
//  WhiteboxCryptographyTests
//
//  Created by Sanjay Dey on 2024-12-10.
//

import XCTest
import CommonCrypto


final class CryptographicServiceTests: XCTestCase {

    var cryptographicService: CryptographicService!

    override func setUp() {
        super.setUp()
        cryptographicService = CryptographicServiceImpl()
    }

    override func tearDown() {
        cryptographicService = nil
        super.tearDown()
    }

    // MARK: - AES Encryption/Decryption Tests
    
    func testAESEncryptionDecryption() {
        // Ensure the key is exactly 32 bytes for AES-256
        let key = Data(repeating: 0x01, count: 32)  // 32-byte key for AES-256
        let iv = cryptographicService.generateRandomIV(forAlgorithm: .aes(keySize: .bits256, mode: .gcm))  // 12 bytes IV for AES-GCM
        let dataToEncrypt = "This is a test".data(using: .utf8)!

        // Encryption
        guard let encryptedData = cryptographicService.encrypt(data: dataToEncrypt, withKey: key, iv: iv, algorithm: .aes(keySize: .bits256, mode: .gcm)) else {
            XCTFail("Encryption failed")
            return
        }

        // Decryption
        guard let decryptedData = cryptographicService.decrypt(data: encryptedData, withKey: key, iv: iv, algorithm: .aes(keySize: .bits256, mode: .gcm)) else {
            XCTFail("Decryption failed")
            return
        }

        // Check if the decrypted data matches the original data
        let decryptedString = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedString, "This is a test")
    }

    // MARK: - HMAC Tests
    
    func testHMAC() {
        let dataToHash = "Test data for HMAC".data(using: .utf8)!
        let key = Data("secret-key".utf8)

        // Generate HMAC
        let hmacData = cryptographicService.hmac(data: dataToHash, key: key)
        XCTAssertNotNil(hmacData, "HMAC generation failed")
        
        // Check HMAC length
        XCTAssertEqual(hmacData!.count, Int(CC_SHA256_DIGEST_LENGTH), "Incorrect HMAC length")
    }

    // MARK: - Key Derivation Tests
    
    func testKeyDerivation() {
        let password = "strongpassword"
        let salt = Data("randomsalt".utf8)

        // Derive key
        let derivedKey = cryptographicService.deriveKey(fromPassword: password, salt: salt, iterations: 4)
        XCTAssertNotNil(derivedKey, "Key derivation failed")
        
        // Check if derived key has correct length
        XCTAssertEqual(derivedKey!.count, kCCKeySizeAES256, "Incorrect key length")
    }
    
    // MARK: - GCM Encryption/Decryption Tests
    
    func testAESGCMEncryptionDecryption() {
        let dataToEncrypt = "Test data for AES GCM".data(using: .utf8)!
        let key = Data("asesdhkssyhbnjushshgtyu78765sgty".utf8) // Ensure this is 32 bytes for AES256
        let iv = cryptographicService.generateRandomIV(forAlgorithm: .aes(keySize: .bits256, mode: .gcm))

        // GCM Encryption
        let encryptedData = cryptographicService.encryptGCM(data: dataToEncrypt, withKey: key, iv: iv!)
        XCTAssertNotNil(encryptedData, "GCM Encryption failed")

        // GCM Decryption
        let decryptedData = cryptographicService.decryptGCM(data: encryptedData!, withKey: key, iv: iv!)
        XCTAssertNotNil(decryptedData, "GCM Decryption failed")
        
        // Check if the decrypted data matches the original data
        let decryptedString = String(data: decryptedData!, encoding: .utf8)
        XCTAssertEqual(decryptedString, "Test data for AES GCM", "Decrypted data does not match the original")
    }
}
