//
//  WhiteboxCryptographySDKTests.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-13.
//


import XCTest
import Foundation
import WhiteboxCryptography

class WhiteboxCryptographySDKTests: XCTestCase {
    
    var sdk: WhiteboxCryptographySDK!

    override func setUp() {
        super.setUp()
        let memoryKey = Data(repeating: 0x01, count: 32) // Memory key for initialization
        sdk = WhiteboxCryptographySDK(memoryKey: memoryKey)
    }
    
    override func tearDown() {
        sdk = nil
        super.tearDown()
    }
    
    // Helper function to test AES encryption and decryption for a specific mode, key size, and IV size
    func testAESMode(mode: AESMode, keySize: Int, ivSize: Int, type: ProcressingType) {
        let originalData = "Hello, AES \(mode)!".data(using: .utf8)!
        let key = Data(repeating: 0x02, count: keySize / 8)
        let iv = Data(repeating: 0x03, count: ivSize)
        
        do {
            let algorithm = CryptoAlgorithm.aes(keySize: keySize, mode: mode, processingType: type)
            
            // Encrypt the data
            let encryptedData = try sdk.encrypt(data: originalData, withKey: key, iv: iv, algorithm: algorithm)
            XCTAssertNotNil(encryptedData, "Encryption failed for AES \(mode) with key size \(keySize) and IV size \(ivSize)")
            
            // Decrypt the data
            let decryptedData = try sdk.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
            XCTAssertEqual(originalData, decryptedData, "Decryption failed for AES \(mode) with key size \(keySize) and IV size \(ivSize)")
        } catch {
            XCTFail("Error testing AES \(mode) with key size \(keySize) and IV size \(ivSize): \(error)")
        }
    }
    
    // Test AES CBC mode with different key sizes, IV size, and "faster" processing type
    func testAESCBCFaster() {
        let keySizes = [128, 192, 256]
        let ivSize = 16 // CBC mode requires a 16-byte IV
        
        for keySize in keySizes {
            testAESMode(mode: .cbc, keySize: keySize, ivSize: ivSize, type: .faster)
        }
    }

    // Test AES CBC mode with different key sizes, IV size, and "regular" processing type
    func testAESCBCRegular() {
        let keySizes = [128, 192, 256]
        let ivSize = 16 // CBC mode requires a 16-byte IV
        
        for keySize in keySizes {
            testAESMode(mode: .cbc, keySize: keySize, ivSize: ivSize, type: .regular)
        }
    }

    // Test AES ECB mode with different key sizes and processing types (no IV required)
    func testAESECBRegular() {
        let keySizes = [128, 192, 256]
        let ivSize = 16
        for keySize in keySizes {
            testAESMode(mode: .ecb, keySize: keySize, ivSize: ivSize, type: .regular)
        }
    }

    // Test AES GCM mode with different key sizes, IV sizes, and "faster" processing type
    func testAESGCMFaster() {
        let keySizes = [256]
        let ivSize = 12 // GCM typically uses a 12-byte IV
        
        for keySize in keySizes {
            testAESMode(mode: .gcm, keySize: keySize, ivSize: ivSize, type: .faster)
        }
    }

    // Test AES GCM mode with different key sizes, IV sizes, and "regular" processing type
    func testAESGCMRegular() {
        let keySizes = [128, 192, 256]
        let ivSize = 12 // GCM typically uses a 12-byte IV
        
        for keySize in keySizes {
            testAESMode(mode: .gcm, keySize: keySize, ivSize: ivSize, type: .regular)
        }
    }

    
    // Test DES algorithm
    func testDES() {
        let keySize = 64 // DES uses a 64-bit key
        let ivSize = 8 // DES requires an 8-byte IV
        let originalData = "Hello, DES!".data(using: .utf8)!
        let key = Data(repeating: 0x04, count: keySize / 8)
        let iv = Data(repeating: 0x05, count: ivSize)
        
        let algorithm = CryptoAlgorithm.des(keySize: keySize, processingType: .faster)
        testAlgorithm(originalData: originalData, algorithm: algorithm, key: key, iv: iv)
    }
    
    // Test Triple DES algorithm
    func testTripleDES() {
        let keySizes = [ 192] // Key sizes for Triple DES
        let ivSize = 8 // Triple DES requires an 8-byte IV
        let originalData = "Hello, Triple DES!".data(using: .utf8)!
        
        for keySize in keySizes {
            let key = Data(repeating: 0x04, count: keySize / 8)
            let iv = Data(repeating: 0x05, count: ivSize)
            let algorithm = CryptoAlgorithm.tripleDES(keySize: keySize, processingType: .faster)
            testAlgorithm(originalData: originalData, algorithm: algorithm, key: key, iv: iv)
        }
    }
    
    // Test RC2 algorithm
    func testRC2() {
        let keySizes = [40, 64, 128] // Key sizes for RC2
        let ivSize = 8 // RC2 requires an 8-byte IV
        let originalData = "Hello, RC2!".data(using: .utf8)!
        
        for keySize in keySizes {
            let key = Data(repeating: 0x06, count: keySize / 8)
            let iv = Data(repeating: 0x07, count: ivSize)
            let algorithm = CryptoAlgorithm.rc2(keySize: keySize, processingType: .faster)
            testAlgorithm(originalData: originalData, algorithm: algorithm, key: key, iv: iv)
        }
    }
    
    // Generalized helper function to test an encryption algorithm
    func testAlgorithm(originalData: Data, algorithm: CryptoAlgorithm, key: Data, iv: Data) {
        do {
            // Encrypt data
            let encryptedData = try sdk.encrypt(data: originalData, withKey: key, iv: iv, algorithm: algorithm)
            XCTAssertNotNil(encryptedData, "Encryption failed for \(algorithm)")
            
            // Decrypt data
            let decryptedData = try sdk.decrypt(data: encryptedData!, withKey: key, iv: iv, algorithm: algorithm)
            XCTAssertEqual(originalData, decryptedData, "Decrypted data does not match original data for \(algorithm)")
        } catch {
            XCTFail("An error occurred during encryption or decryption for \(algorithm): \(error)")
        }
    }
    
    func testCASTRegular() {
        let algorithm = CryptoAlgorithm.cast(keySize: 40, processingType: .faster)
        let keySizes = [40] // Key sizes for RC2
        let ivSize = 8 //
        let originalData = "Hello, CAST!".data(using: .utf8)!

        
        for keySize in keySizes {
            let key = Data(repeating: 0x06, count: keySize / 8)
            let iv = Data(repeating: 0x07, count: ivSize)
            testAlgorithm(originalData: originalData, algorithm: algorithm, key: key, iv: iv)
        }
    }

    
    // Test all algorithms together
    func testAllCombinations() {
        // AES CBC mode tests for both processing types
        testAESCBCFaster()
        testAESCBCRegular()
        
        // AES ECB mode tests for processing types
        testAESECBRegular()
        
        // AES GCM mode tests for both processing types
        testAESGCMFaster()
        testAESGCMRegular()
        
        // DES algorithm tests
        testDES()
        
        // Triple DES algorithm tests
        testTripleDES()
        
        // RC2 algorithm tests
        testRC2()
    }

}
