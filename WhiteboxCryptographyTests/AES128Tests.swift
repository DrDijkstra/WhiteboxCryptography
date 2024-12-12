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
    
    

    func testSBoxAndInverseSBox() {
        // S-box and Inverse S-box values (replace with your actual arrays)
        let sbox = aes128.sbox
        let inverseSbox = aes128.inverseSbox

        // Validate lengths
        XCTAssertEqual(sbox.count, 256, "S-box should have 256 entries.")
        XCTAssertEqual(inverseSbox.count, 256, "Inverse S-box should have 256 entries.")

        // Validate S-box and Inverse S-box relationship
        for x in 0..<256 {
            let sboxValue = sbox[x]
            let inverseValue = inverseSbox[Int(sboxValue)]
            XCTAssertEqual(inverseValue, UInt8(x), "InverseSbox[Sbox[\(x)]] should be \(x), but got \(inverseValue).")
        }

        // Validate uniqueness
        XCTAssertEqual(Set(sbox).count, 256, "S-box should have unique values.")
        XCTAssertEqual(Set(inverseSbox).count, 256, "Inverse S-box should have unique values.")
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
        
    func testEncryptDecryptData() {
        // Sample plaintext message (less than 16 bytes)
        let plaintext: [UInt8] = Array("Helloasdfghthght".utf8) // Length 16
        // Initialization Vector (IV) - 16 bytes (128 bits)
        let iv: [UInt8] = Array(repeating: 0x00, count: 16) // Simple 16-byte IV (can be random)
        
        // Encrypt the data
        let encryptedData = aes128.encryptData(data: plaintext, iv: iv)
        print("Encrypted Data: \(encryptedData.asciiCharactersString)")  // For debugging

        // Decrypt the encrypted data
        let decryptedData = aes128.decryptData(data: encryptedData, iv: iv)
        
        // Check that the decrypted data matches the original plaintext
        XCTAssertEqual(decryptedData, plaintext, "Decrypted data should match the original plaintext.")
        
        // Optionally, print the encrypted and decrypted data for manual inspection
        print("Plaintext: \(String(bytes: plaintext, encoding: .utf8)!)")
        print("Encrypted Data: \(encryptedData.hexString)")
        print("Decrypted Data: \(decryptedData.hexString)")
        print("Decrypted Data: \(String(bytes: decryptedData, encoding: .utf8)!)")
    }

}
