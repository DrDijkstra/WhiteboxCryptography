//
//  AES128Tests.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//


import XCTest

class AES128Tests: XCTestCase {

    var aes128: AES128!
    var testKey: [UInt8]!

    override func setUp() {
        super.setUp()
        
        // Set up a 128-bit key for AES-128 (16 bytes)
        testKey = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x97, 0x75, 0x46, 0x15, 0x54, 0x17
        ]
        
        // Initialize AES128 with the test key
        aes128 = AES128(key: testKey)
    }

    func testEncryptionAndDecryption() {
        // Sample plaintext (16 bytes block)
        let plaintext: [UInt8] = [
            0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
            0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34
        ]
        
        // Encrypt the plaintext
        let ciphertext = aes128.encrypt(block: plaintext)
        
        // Decrypt the ciphertext
        let decryptedText = aes128.decrypt(block: ciphertext)
        
        // Verify that the decrypted text matches the original plaintext
        XCTAssertEqual(plaintext, decryptedText, "Decrypted text does not match the original plaintext.")
    }
}
