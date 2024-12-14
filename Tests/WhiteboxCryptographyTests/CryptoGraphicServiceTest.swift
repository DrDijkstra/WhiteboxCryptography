//
//  CryptoGraphicServiceTest.swift
//  WhiteboxCryptographyTests
//
//  Created by Sanjay Dey on 2024-12-10.
//

import XCTest
import CommonCrypto
@testable import WhiteboxCryptography

class CryptographicServiceTests: XCTestCase {

    var cryptographicService: CryptographicServiceImpl!

    override func setUp() {
        super.setUp()
        cryptographicService = CryptographicServiceImpl()
    }

    // MARK: - AES Encryption/Decryption
    func testAES() {
        let testData = "Test data for AES encryption".data(using: .utf8)!
        
        let algorithms: [CryptoAlgorithm] = [
            .aes(keySize: 128, mode: .cbc, processingType: .regular),
            .aes(keySize: 192, mode: .cbc, processingType: .regular),
            .aes(keySize: 256, mode: .cbc, processingType: .regular),
            .aes(keySize: 256, mode: .gcm, processingType: .faster)
        ]

        for algorithm in algorithms {
            do {
                // Dynamically generate the key based on the algorithm's key size
                let keySizeInBytes = algorithm.keySize / 8
                print("keySizeInBytes \(keySizeInBytes)")
                let key = Data(repeating: 0x01, count: keySizeInBytes)

                // Dynamically generate the IV based on the algorithm's IV size
                let iv = Data(repeating: 0x01, count: algorithm.ivSize)

                // Encrypt the data
                let encryptedData = try cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(encryptedData)

                // Decrypt the data
                let decryptedData = try cryptographicService.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(decryptedData)
                XCTAssertEqual(testData, decryptedData)

            } catch {
                XCTFail("Encryption/Decryption failed with error: \(error)")
            }
        }
    }

    // MARK: - DES Encryption/Decryption
    func testDES() {
        let testData = "Test data for DES encryption".data(using: .utf8)!
        let key = Data(repeating: 0x01, count: 8) // DES key size 56 bits
        let iv = Data(repeating: 0x01, count: 8) // DES IV size 8 bytes

        let algorithms: [CryptoAlgorithm] = [
            .des(keySize: 56, processingType: .faster),
            .des(keySize: 56, processingType: .regular)
        ]

        for algorithm in algorithms {
            do {
                let encryptedData = try cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(encryptedData)

                let decryptedData = try cryptographicService.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(decryptedData)
                XCTAssertEqual(testData, decryptedData)

            } catch {
                XCTFail("Encryption/Decryption failed with error: \(error)")
            }
        }
    }

    // MARK: - Triple DES Encryption/Decryption
    func testTripleDES() {
        let testData = "Test data for Triple DES encryption".data(using: .utf8)!
        let key = Data(repeating: 0x01, count: 24) // Triple DES key size (112 or 168 bits)
        let iv = Data(repeating: 0x01, count: 8) // 8-byte IV for Triple DES

        let algorithms: [CryptoAlgorithm] = [
            .tripleDES(keySize: 112, processingType: .faster),
            .tripleDES(keySize: 168, processingType: .faster),
            .tripleDES(keySize: 168, processingType: .regular),
            .tripleDES(keySize: 168, processingType: .regular),
        ]

        for algorithm in algorithms {
            do {
                let encryptedData = try cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(encryptedData)

                let decryptedData = try cryptographicService.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(decryptedData)
                XCTAssertEqual(testData, decryptedData)

            } catch {
                XCTFail("Encryption/Decryption failed with error: \(error)")
            }
        }
    }

    // MARK: - CAST Encryption/Decryption
    func testCAST() {
        let testData = "Test data for CAST encryption".data(using: .utf8)!
        let key = Data(repeating: 0x01, count: 5) // CAST key size 40 bits
        let iv = Data(repeating: 0x01, count: 8) // 8-byte IV for CAST

        let algorithms: [CryptoAlgorithm] = [
            .cast(keySize: 40, processingType: .faster),
            .cast(keySize: 40, processingType: .regular)
        ]

        for algorithm in algorithms {
            do {
                let encryptedData = try cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(encryptedData)

                let decryptedData = try cryptographicService.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(decryptedData)
                XCTAssertEqual(testData, decryptedData)

            } catch {
                XCTFail("Encryption/Decryption failed with error: \(error)")
            }
        }
    }

    // MARK: - RC2 Encryption/Decryption
    func testRC2() {
        let testData = "Test data for RC2 encryption".data(using: .utf8)!
        let key = Data(repeating: 0x01, count: 8) // RC2 can vary in key size, here we test with 8 bytes (64 bits)
        let iv = Data(repeating: 0x01, count: 8) // 8-byte IV for RC2

        let algorithms: [CryptoAlgorithm] = [
            .rc2(keySize: 64, processingType: .faster),
            .rc2(keySize: 128, processingType: .faster),
            .rc2(keySize: 256, processingType: .faster),
            .rc2(keySize: 64, processingType: .regular),
            .rc2(keySize: 128, processingType: .regular),
            .rc2(keySize: 256, processingType: .regular)
        ]

        for algorithm in algorithms {
            do {
                let encryptedData = try cryptographicService.encrypt(data: testData, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(encryptedData)

                let decryptedData = try cryptographicService.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
                XCTAssertNotNil(decryptedData)
                XCTAssertEqual(testData, decryptedData)

            } catch {
                XCTFail("Encryption/Decryption failed with error: \(error)")
            }
        }
    }

    // MARK: - Helper Function to Test Random Key Generation
//    func testRandomKeyGeneration() {
//        let algorithms: [CryptoAlgorithm] = [
//            .aes(keySize: 128, mode: .cbc, processingType: .regular),
//            .aes(keySize: 256, mode: .gcm, processingType: .faster),
//            .des(keySize: 56),
//            .tripleDES(keySize: 168),
//            .cast(keySize: 40),
//            .rc2(keySize: 64)
//        ]
//
//        for algorithm in algorithms {
//            if let randomKey = cryptographicService.generateRandomKey(forAlgorithm: algorithm) {
//                // Check the generated key's byte count against the expected size in bytes
//                XCTAssertEqual(randomKey.count, algorithm.validKeySizes.first!.keySizeInBytes)
//            } else {
//                XCTFail("Random key generation failed for algorithm \(algorithm)")
//            }
//        }
//    }
}
