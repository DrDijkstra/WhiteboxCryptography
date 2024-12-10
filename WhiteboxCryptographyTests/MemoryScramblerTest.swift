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

    // Test scramble and descramble with AES
    func testAES_ScrambleDescramble() {
        let scrambledData = memoryScrambler.scrambleWithAES(data: testData, withKey: testKey)
        let descrambledData = memoryScrambler.descrambleWithAES(data: scrambledData!, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "AES scrambled and descrambled data should be equal")
    }

    // Test scramble and descramble with XOR
    func testXOR_ScrambleDescramble() {
        let scrambledData = memoryScrambler.scrambleWithXOR(data: testData, withKey: testKey)
        let descrambledData = memoryScrambler.descrambleWithXOR(data: scrambledData, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "XOR scrambled and descrambled data should be equal")
    }

    // Test scramble and descramble with Byte Shift
    func testShift_ScrambleDescramble() {
        let scrambledData = memoryScrambler.scrambleWithShift(data: testData, shiftAmount: 3)
        let descrambledData = memoryScrambler.scrambleWithShift(data: scrambledData, shiftAmount: -3)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "Byte Shift scrambled and descrambled data should be equal")
    }

    // Test scramble with Hashing (though it's not reversible, the resulting data should be different)
    func testHashing_Scramble() {
        let scrambledData = memoryScrambler.scrambleWithHashing(data: testData)
        
        // Assert that the scrambled data is not equal to the original data (since hashing modifies the data)
        XCTAssertNotEqual(testData, scrambledData, "Hashing should scramble the data")
    }

    // Test multi-threading scramble and descramble (this tests multi-threaded XOR operation)
    func testMultiThreading_ScrambleDescramble() {
        let scrambledData = memoryScrambler.scrambleWithMultiThreading(data: testData, withKey: testKey)
        let descrambledData = memoryScrambler.descrambleWithMultiThreading(data: scrambledData, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "Multi-threaded XOR scrambled and descrambled data should be equal")
    }

    // Test full scrambling with all techniques and descrambling
    func testFullScrambleDescramble() {
        let scrambledData = memoryScrambler.scramble(data: testData, withKey: testKey)
        let descrambledData = memoryScrambler.descramble(data: scrambledData, withKey: testKey)
        
        // Assert that the original data is returned after descrambling
        XCTAssertEqual(testData, descrambledData, "Full scramble and descramble should result in the original data")
    }
}
