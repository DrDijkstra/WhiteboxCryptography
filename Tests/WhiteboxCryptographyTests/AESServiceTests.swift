//
//  AESServiceImplTests.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import XCTest
import WhiteboxCryptography

class AESServiceImplTests: XCTestCase {

    var aesService: AESServiceImpl!

    override func setUp() {
        super.setUp()
        aesService = AESServiceImpl()
    }

    override func tearDown() {
        aesService = nil
        super.tearDown()
    }

    func testEncryptDecrypt128BitKeyECB() throws {
        try performTest(keySize: 16, mode: .ecb)
    }

    func testEncryptDecrypt192BitKeyECB() throws {
        try performTest(keySize: 24, mode: .ecb)
    }

    func testEncryptDecrypt256BitKeyECB() throws {
        try performTest(keySize: 32, mode: .ecb)
    }

    func testEncryptDecrypt128BitKeyCBC() throws {
        try performTest(keySize: 16, mode: .cbc)
    }

    func testEncryptDecrypt192BitKeyCBC() throws {
        try performTest(keySize: 24, mode: .cbc)
    }

    func testEncryptDecrypt256BitKeyCBC() throws {
        try performTest(keySize: 32, mode: .cbc)
    }

    private func performTest(keySize: Int, mode: AESMode) throws {
        let key = generateRandomBytes(count: keySize)
        let block = generateRandomBytes(count: 16) // AES block size is 16 bytes
        let iv = (mode == .cbc || mode == .ecb) ? generateRandomBytes(count: 16) : generateRandomBytes(count: 12)


        // Encrypt
        let encryptedData = try aesService.encrypt(block: Data(block), key: Data(key), iv: Data(iv), mode: mode)
        XCTAssertNotNil(encryptedData, "Encryption failed")

        // Decrypt
        let decryptedData = try aesService.decrypt(block: encryptedData!, key: Data(key), iv:  Data(iv), mode: mode)
        XCTAssertNotNil(decryptedData, "Decryption failed")

        // Validate
        XCTAssertEqual(Data(block), decryptedData, "Decrypted data does not match original")
    }

    private func generateRandomBytes(count: Int) -> [UInt8] {
        return (0..<count).map { _ in UInt8.random(in: 0...255) }
    }
}
