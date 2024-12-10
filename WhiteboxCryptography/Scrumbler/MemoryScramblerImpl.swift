//
//  MemoryScrambler.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CryptoKit

/// Implementation of memory scrambling and descrambling using various cryptographic techniques.
class MemoryScramblerImpl: MemoryScrambler {

    /// Scrambles the provided data using a combination of XOR, byte shifting, AES encryption, and multi-threaded XOR.
    ///
    /// - Parameters:
    ///   - data: The data to be scrambled.
    ///   - key: The key used for scrambling.
    /// - Returns: The scrambled data.
    func scramble(data: Data, withKey key: Data) -> Data {
        var scrambledData = applyXORScrambling(to: data, withKey: key)
        scrambledData = applyByteShiftScrambling(to: scrambledData, by: 3)
        if let aesScrambled = applyAESScrambling(to: scrambledData, withKey: key) {
            scrambledData = aesScrambled
        }
        scrambledData = applyMultiThreadedXORScrambling(to: scrambledData, withKey: key)
        return scrambledData
    }

    /// Descrambles the provided data using the reverse of the scrambling techniques.
    ///
    /// - Parameters:
    ///   - data: The data to be descrambled.
    ///   - key: The key used for descrambling.
    /// - Returns: The descrambled data.
    func descramble(data: Data, withKey key: Data) -> Data {
        var descrambledData = applyMultiThreadedXORScrambling(to: data, withKey: key)

        if let aesDescrambled = reverseAESScrambling(from: descrambledData, withKey: key) {
            descrambledData = aesDescrambled
        }

        descrambledData = applyByteShiftScrambling(to: descrambledData, by: -3)
        descrambledData = applyXORScrambling(to: descrambledData, withKey: key)
        return descrambledData
    }

    // MARK: - Scrambling Techniques

    /// Scrambles the data using AES encryption.
    func applyAESScrambling(to data: Data, withKey key: Data) -> Data? {
        let aesKey = SymmetricKey(data: key.prefix(32)) // Use first 256 bits if longer
        
        do {
            let sealedBox = try AES.GCM.seal(data, using: aesKey)
            return sealedBox.combined
        } catch {
            return nil
        }
    }

    /// Descrambles the data using AES decryption.
    func reverseAESScrambling(from data: Data, withKey key: Data) -> Data? {
        let aesKey = SymmetricKey(data: key.prefix(32)) // Use first 256 bits if longer
        
        do {
            let box = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(box, using: aesKey)
            return decryptedData
        } catch {
            return nil
        }
    }

    /// Scrambles the data using XOR (simple reversible scrambling).
    func applyXORScrambling(to data: Data, withKey key: Data) -> Data {
        var scrambledData = [UInt8](repeating: 0, count: data.count)
        let keyCount = key.count
        
        // Scramble each byte using XOR
        for i in 0..<data.count {
            let keyIndex = i % keyCount
            scrambledData[i] = data[i] ^ key[keyIndex]
        }
        
        return Data(scrambledData)
    }

    /// Scrambles the data using a simple byte-shift method.
    func applyByteShiftScrambling(to data: Data, by shiftAmount: Int) -> Data {
        var scrambledData = [UInt8](repeating: 0, count: data.count)
        
        for i in 0..<data.count {
            let shiftedValue = (Int(data[i]) + shiftAmount) % 256
            scrambledData[i] = shiftedValue >= 0 ? UInt8(shiftedValue) : UInt8(shiftedValue + 256)
        }
        
        return Data(scrambledData)
    }

    /// Scrambles the data using multi-threading for faster performance on large datasets.
    func applyMultiThreadedXORScrambling(to data: Data, withKey key: Data) -> Data {
        var scrambledData = [UInt8](repeating: 0, count: data.count)
        let keyCount = key.count
        let queue = DispatchQueue(label: "com.memoryscrambler.concurrent", attributes: .concurrent)
        let group = DispatchGroup()
        
        let chunkCount = 8
        let chunkSize = (data.count + chunkCount - 1) / chunkCount
        
        for chunkIndex in 0..<chunkCount {
            queue.async(group: group) {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min((chunkIndex + 1) * chunkSize, data.count)
                
                guard startIndex < endIndex else { return }
                
                for i in startIndex..<endIndex {
                    let keyIndex = i % keyCount
                    scrambledData[i] = data[i] ^ key[keyIndex]
                }
            }
        }
        
        group.wait()
        return Data(scrambledData)
    }

}
