//
//  MemoryScramblerTest.swift
//  WhiteboxCryptographyTests
//
//  Created by Sanjay Dey on 2024-12-10.
//
import XCTest
import CryptoKit
import WhiteboxCryptography

final class MemoryScramblerTests: XCTestCase {

    var memoryScrambler: MemoryScramblerImpl!
    var testKey: Data!
    var testData: Data!

    override func setUp() {
        super.setUp()
        memoryScrambler = MemoryScramblerImpl()
        testKey = "sampleEncryptionKeysampleEncryptionKeysampleEncryptionKey".data(using: .utf8)!
    }

    override func tearDown() {
        memoryScrambler = nil
        testKey = nil
        super.tearDown()
    }

    // Test AES scramble and descramble for multiple data sizes
    func testAES_ScrambleDescrambleForDifferentDataSizes() {
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)
            
            guard let scrambledData = memoryScrambler.applyAESScrambling(to: testData, withKey: testKey) else {
                XCTFail("AES scrambling failed for data size: \(size)")
                return
            }
            
            guard let descrambledData = memoryScrambler.reverseAESScrambling(from: scrambledData, withKey: testKey) else {
                XCTFail("AES descrambling failed for data size: \(size)")
                return
            }
            
            // Assert that the original data is returned after descrambling
            XCTAssertEqual(testData, descrambledData, "AES scrambled and descrambled data should be equal for size: \(size)")
        }
    }

    // Test XOR scramble and descramble for multiple data sizes
    func testXOR_ScrambleDescrambleForDifferentDataSizes() {
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)
            
            let scrambledData = memoryScrambler.applyXORScrambling(to: testData, withKey: testKey)
            let descrambledData = memoryScrambler.applyXORScrambling(to: scrambledData, withKey: testKey)
            
            // Assert that the original data is returned after descrambling
            XCTAssertEqual(testData, descrambledData, "XOR scrambled and descrambled data should be equal for size: \(size)")
        }
    }

    // Test Byte Shift scramble and descramble for multiple data sizes
    func testShift_ScrambleDescrambleForDifferentDataSizes() {
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)
            
            let scrambledData = memoryScrambler.applyByteShiftScrambling(to: testData, by: 3)
            let descrambledData = memoryScrambler.applyByteShiftScrambling(to: scrambledData, by: -3)
            
            // Assert that the original data is returned after descrambling
            XCTAssertEqual(testData, descrambledData, "Byte Shift scrambled and descrambled data should be equal for size: \(size)")
        }
    }

    // Test multi-threading scramble and descramble for multiple data sizes
    func testMultiThreading_ScrambleDescrambleForDifferentDataSizes() {
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)
            
            let scrambledData = memoryScrambler.applyMultiThreadedXORScrambling(to: testData, withKey: testKey)
            let descrambledData = memoryScrambler.applyMultiThreadedXORScrambling(to: scrambledData, withKey: testKey)
            
            // Assert that the original data is returned after descrambling
            XCTAssertEqual(testData, descrambledData, "Multi-threaded XOR scrambled and descrambled data should be equal for size: \(size)")
        }
    }

    // Test full scramble and descramble using all techniques for multiple data sizes
    func testFullScrambleDescrambleForDifferentDataSizes() {
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)
            
            let scrambledData = memoryScrambler.scramble(data: testData, withKey: testKey)
            let descrambledData = memoryScrambler.descramble(data: scrambledData, withKey: testKey)
            
            // Assert that the original data is returned after descrambling
            XCTAssertEqual(testData, descrambledData, "Full scramble and descramble should result in the original data for size: \(size)")
        }
    }

    // Test hashing (scrambling isn't reversible, so it shouldn't match the original data)
    func testHashing_ScrambleForDifferentDataSizes() {
        let dataSizes: [Int] = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
        
        for size in dataSizes {
            let testData = Data(repeating: 0x01, count: size)
            
            let scrambledData = memoryScrambler.applyXORScrambling(to: testData, withKey: testKey)
            
            // Assert that the scrambled data is not equal to the original data
            XCTAssertNotEqual(testData, scrambledData, "XOR scrambling should change the data for size: \(size)")
        }
    }
}
