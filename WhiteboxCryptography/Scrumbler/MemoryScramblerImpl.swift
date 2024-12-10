//
//  MemoryScrambler.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//


import Foundation

class MemoryScramblerImpl: MemoryScrambler {

    // Scramble the bytes of the input data using a simple XOR-based algorithm
    func scramble(data: Data, withKey key: Data) -> Data {
        var scrambledData = [UInt8](data)
        var keyIndex = 0
        
        for i in 0..<scrambledData.count {
            scrambledData[i] ^= key[keyIndex]
            keyIndex = (keyIndex + 1) % key.count // Loop the key if it's shorter than the data
        }
        
        return Data(scrambledData)
    }

    // Descramble the bytes (same as scramble, as XOR is reversible)
    func descramble(data: Data, withKey key: Data) -> Data {
        return scramble(data: data, withKey: key) // XOR is symmetric
    }
}
