//
//  CryptoGraphicServiceTest.swift
//  WhiteboxCryptographyTests
//
//  Created by Sanjay Dey on 2024-12-10.
//

import XCTest
import CommonCrypto

final class CryptographicServiceTests: XCTestCase {

    var cryptographicService: CryptographicServiceImpl!

    override func setUp() {
        super.setUp()
        cryptographicService = CryptographicServiceImpl()
    }

    override func tearDown() {
        cryptographicService = nil
        super.tearDown()
    }

    // MARK: - AES Encryption/Decryption Tests for Array of Data Sizes
    
    func testAESEncryptionDecryptionForDifferentDataSizes() {
        // Generate a list of different data sizes (e.g., 1KB, 10KB, 100KB, 1MB, 10MB)
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]

        // Iterate over each data size
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)  // Generate data of specified size
            let key = Data(repeating: 0x01, count: 32)  // 32-byte key for AES-256
            let iv = cryptographicService.generateRandomIV(forAlgorithm: .aes(keySize: .bits256, mode: .gcm))  // 12 bytes IV for AES-GCM

            // Encryption
            guard let encryptedData = try? cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: .aes(keySize: .bits256, mode: .gcm)) else {
                XCTFail("Encryption failed for data size: \(size)")
                return
            }

            // Decryption
            guard let decryptedData = try? cryptographicService.decrypt(data: encryptedData, withKey: key, iv: iv, algorithm: .aes(keySize: .bits256, mode: .gcm)) else {
                XCTFail("Decryption failed for data size: \(size)")
                return
            }

            // Check if the decrypted data matches the original data
            XCTAssertEqual(decryptedData, testData, "Decrypted data does not match the original data for size: \(size)")
        }
    }

    // MARK: - HMAC Tests for Array of Data Sizes
    
    func testHMACForDifferentDataSizes() {
        // Generate a list of different data sizes (e.g., 1KB, 10KB, 100KB, 1MB, 10MB)
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        let key = Data("secret-key".utf8)

        // Iterate over each data size
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)  // Generate data of specified size

            // Generate HMAC
            guard let hmacData = cryptographicService.hmac(data: testData, key: key) else {
                XCTFail("HMAC generation failed for data size: \(size)")
                return
            }

            // Check HMAC length
            XCTAssertEqual(hmacData.count, Int(CC_SHA256_DIGEST_LENGTH), "Incorrect HMAC length for data size: \(size)")
        }
    }

    // MARK: - Key Derivation Tests for Array of Data Sizes
    
    func testKeyDerivationForDifferentDataSizes() {
        // Generate a list of different data sizes (e.g., 1KB, 10KB, 100KB, 1MB, 10MB)
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        let password = "strongpassword"
        let salt = Data("randomsalt".utf8)

        // Iterate over each data size
        for size in dataSizes {
            // Derive key
            guard let derivedKey = cryptographicService.deriveKey(fromPassword: password, salt: salt, iterations: 4) else {
                XCTFail("Key derivation failed for data size: \(size)")
                return
            }

            // Check if derived key has correct length
            XCTAssertEqual(derivedKey.count, kCCKeySizeAES256, "Incorrect key length for data size: \(size)")
        }
    }

    // MARK: - AES GCM Encryption/Decryption Tests
    
    func testAESGCMEncryptionDecryptionForDifferentDataSizes() {
        // Generate a list of different data sizes (e.g., 1KB, 10KB, 100KB, 1MB, 10MB)
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]

        // Iterate over each data size
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)  // Generate data of specified size
            let key = Data("asesdhkssyhbnjushshgtyu78765sgty".utf8) // Ensure this is 32 bytes for AES256
            let iv = cryptographicService.generateRandomIV(forAlgorithm: .aes(keySize: .bits256, mode: .gcm))!

            // GCM Encryption
            guard let encryptedData = try? cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: .aes(keySize: .bits256, mode: .gcm)) else {
                XCTFail("GCM Encryption failed for data size: \(size)")
                return
            }

            // GCM Decryption
            guard let decryptedData = try? cryptographicService.decrypt(data: encryptedData, withKey: key, iv: iv, algorithm: .aes(keySize: .bits256, mode: .gcm)) else {
                XCTFail("GCM Decryption failed for data size: \(size)")
                return
            }

            // Check if the decrypted data matches the original data
            XCTAssertEqual(decryptedData, testData, "Decrypted data does not match the original data for size: \(size)")
        }
    }
}
