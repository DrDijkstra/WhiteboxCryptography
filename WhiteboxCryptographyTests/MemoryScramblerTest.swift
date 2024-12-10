//
//  MemoryScramblerTest.swift
//  WhiteboxCryptographyTests
//
//  Created by Sanjay Dey on 2024-12-10.
//
import XCTest
import CryptoKit

final class MemoryScramblerTests: XCTestCase {

    var memoryScrambler: MemoryScramblerImpl!
    var testKey: Data!
    var testData: Data!

    override func setUp() {
        super.setUp()
        memoryScrambler = MemoryScramblerImpl()
        testKey = "sampleEncryptionKeysampleEncryptionKeysampleEncryptionKey".data(using: .utf8)!
        testData = "This is a test string. This is a test string..This is a test string.This is a test string.This is a test string.This is a test string.This is a test string.".data(using: .utf8)!
    }

    override func tearDown() {
        memoryScrambler = nil
        testKey = nil
        testData = nil
        super.tearDown()
    }

    // Test AES scramble and descramble
    func testAES_ScrambleDescramble() {
        guard let scrambledData = memoryScrambler.applyAESScrambling(to: testData, withKey: testKey) else {
            XCTFail("AES scrambling failed")
            return
        }
        
        guard let descrambledData = memoryScrambler.reverseAESScrambling(from: scrambledData, withKey: testKey) else {
            XCTFail("AES descrambling failed")
            return
        }
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "AES scrambled and descrambled data should be equal")
    }

    // Test XOR scramble and descramble
    func testXOR_ScrambleDescramble() {
        let scrambledData = memoryScrambler.applyXORScrambling(to: testData, withKey: testKey)
        let descrambledData = memoryScrambler.applyXORScrambling(to: scrambledData, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "XOR scrambled and descrambled data should be equal")
    }

    // Test Byte Shift scramble and descramble
    func testShift_ScrambleDescramble() {
        let scrambledData = memoryScrambler.applyByteShiftScrambling(to: testData, by: 3)
        let descrambledData = memoryScrambler.applyByteShiftScrambling(to: scrambledData, by: -3)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "Byte Shift scrambled and descrambled data should be equal")
    }

    // Test multi-threading scramble and descramble (this tests multi-threaded XOR operation)
    func testMultiThreading_ScrambleDescramble() {
        let scrambledData = memoryScrambler.applyMultiThreadedXORScrambling(to: testData, withKey: testKey)
        let descrambledData = memoryScrambler.reverseMultiThreadedXORDescrambling(from: scrambledData, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "Multi-threaded XOR scrambled and descrambled data should be equal")
    }

    // Test full scramble and descramble using all techniques
    func testFullScrambleDescramble() {
        let scrambledData = memoryScrambler.scramble(data: testData, withKey: testKey)
        let descrambledData = memoryScrambler.descramble(data: scrambledData, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "Full scramble and descramble should result in the original data")
    }

    // Test hashing (scrambling isn't reversible, so it shouldn't match the original data)
    func testHashing_Scramble() {
        let scrambledData = memoryScrambler.applyXORScrambling(to: testData, withKey: testKey)
        
        // Assert that the scrambled data is not equal to the original data
        XCTAssertNotEqual(testData, scrambledData, "XOR scrambling should change the data")
    }

}
