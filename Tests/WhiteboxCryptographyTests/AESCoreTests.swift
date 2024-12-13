//
//  AESCoreTests.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import XCTest
import WhiteboxCryptography

class AESCoreTests: XCTestCase {

    var aesCore: AESCore!

    override func setUp() {
        super.setUp()
        aesCore = AESCore() // Initialize AESCore
    }

    override func tearDown() {
        aesCore = nil // Clean up after each test
        super.tearDown()
    }

    // Helper function to convert a string to a UInt8 array
    private func ivFromString(_ ivString: String) -> [UInt8] {
        return Array(ivString.utf8)
    }

    // 128-bit Key Tests
    func testAESEncryptionDecryptionECB_128() throws {
        try testAESEncryptionDecryption(key: [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x75, 0x46, 0x7d, 0x6f, 0x36
        ], mode: .ecb, iv: "0123456789ab")
    }

    func testAESEncryptionDecryptionCBC_128() throws {
        try testAESEncryptionDecryption(key: [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x75, 0x46, 0x7d, 0x6f, 0x36
        ], mode: .cbc, iv: "2123bshjkllnsyhj")
    }

    func testAESEncryptionDecryptionGCM_128() throws {
        try testAESEncryptionDecryption(key: [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x75, 0x46, 0x7d, 0x6f, 0x36
        ], mode: .gcm, iv: "1234567890ab")
    }

    // 192-bit Key Tests
    func testAESEncryptionDecryptionECB_192() throws {
        try testAESEncryptionDecryption(key: [
            0x8e, 0x73, 0x5c, 0x90, 0x7b, 0x56, 0x3c, 0x60,
            0x28, 0x43, 0x2d, 0x7f, 0x70, 0x35, 0x5a, 0x0e,
            0x85, 0x58, 0x60, 0x92, 0x19, 0x29, 0x66, 0x58
        ], mode: .ecb, iv: "abcdef123456")
    }

    func testAESEncryptionDecryptionCBC_192() throws {
        try testAESEncryptionDecryption(key: [
            0x8e, 0x73, 0x5c, 0x90, 0x7b, 0x56, 0x3c, 0x60,
            0x28, 0x43, 0x2d, 0x7f, 0x70, 0x35, 0x5a, 0x0e,
            0x85, 0x58, 0x60, 0x92, 0x19, 0x29, 0x66, 0x58
        ], mode: .cbc, iv: "2345shjklddyhjbt")
    }

    func testAESEncryptionDecryptionGCM_192() throws {
        try testAESEncryptionDecryption(key: [
            0x8e, 0x73, 0x5c, 0x90, 0x7b, 0x56, 0x3c, 0x60,
            0x28, 0x43, 0x2d, 0x7f, 0x70, 0x35, 0x5a, 0x0e,
            0x85, 0x58, 0x60, 0x92, 0x19, 0x29, 0x66, 0x58
        ], mode: .gcm, iv: "9876543210ab")
    }

    // 256-bit Key Tests
    func testAESEncryptionDecryptionECB_256() throws {
        try testAESEncryptionDecryption(key: [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x61, 0x1d, 0x72, 0x10, 0x84, 0x47,
            0x9b, 0x6d, 0x7a, 0x96, 0x1e, 0x18, 0x7a, 0x6e
        ], mode: .ecb, iv: "abcdef12345678")
    }

    func testAESEncryptionDecryptionCBC_256() throws {
        try testAESEncryptionDecryption(key: [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x61, 0x1d, 0x72, 0x10, 0x84, 0x47,
            0x9b, 0x6d, 0x7a, 0x96, 0x1e, 0x18, 0x7a, 0x6e
        ], mode: .cbc, iv: "9876543210abcdef")
    }

    func testAESEncryptionDecryptionGCM_256() throws {
        try testAESEncryptionDecryption(key: [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x61, 0x1d, 0x72, 0x10, 0x84, 0x47,
            0x9b, 0x6d, 0x7a, 0x96, 0x1e, 0x18, 0x7a, 0x6e
        ], mode: .gcm, iv: "9876543210ab")
    }

    // Helper function to run encryption and decryption for a given key, mode, and iv
    private func testAESEncryptionDecryption(key: [UInt8], mode: AESMode, iv ivString: String) throws {
        let plaintext: [UInt8] = [
            0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
            0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34
        ]
        let iv: [UInt8] = ivFromString(ivString)

        try aesCore.update(key: key, mode: mode)

        // Encrypt the plaintext
        let encryptedData = try aesCore.encryptData(data: plaintext, iv: iv)
        XCTAssertNotEqual(plaintext, encryptedData, "Encryption failed, data is the same for key size \(key.count * 8) bits and mode \(mode)")

        // Decrypt the ciphertext
        let decryptedData = try aesCore.decryptData(data: encryptedData, iv: iv)

        // Verify the decrypted data matches the original plaintext
        XCTAssertEqual(plaintext, decryptedData, "Decrypted data does not match the original plaintext for key size \(key.count * 8) bits and mode \(mode)")
    }
    

}
