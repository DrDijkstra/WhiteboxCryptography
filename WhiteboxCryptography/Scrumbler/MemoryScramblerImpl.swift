//
//  MemoryScrambler.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CryptoKit

/// Implementation of memory scrambling and descrambling using various cryptographic techniques.
public class MemoryScramblerImpl: MemoryScrambler {

    /// Scrambles the provided data using a combination of XOR, byte shifting, AES encryption, and multi-threaded XOR.
    ///
    /// - Parameters:
    ///   - data: The data to be scrambled.
    ///   - key: The key used for scrambling.
    /// - Returns: The scrambled data.
    public func scramble(data: Data, withKey key: Data) -> Data {
        var scrambledData = data

        // Apply XOR Scrambling
        scrambledData = applyXORScrambling(to: scrambledData, withKey: key)

        // Apply Byte Shift Scrambling
        scrambledData = applyByteShiftScrambling(to: scrambledData, by: 3)

        // Apply AES Scrambling
        if let aesScrambled = applyAESScrambling(to: scrambledData, withKey: key) {
            scrambledData = aesScrambled
        }

        // Apply Multi-threaded XOR Scrambling
        scrambledData = applyMultiThreadedXORScrambling(to: scrambledData, withKey: key)

        return scrambledData
    }

    /// Descrambles the provided data using the reverse of the scrambling techniques.
    ///
    /// - Parameters:
    ///   - data: The data to be descrambled.
    ///   - key: The key used for descrambling.
    /// - Returns: The descrambled data.
    public func descramble(data: Data, withKey key: Data) -> Data {
        var descrambledData = data

        // Reverse Multi-threaded XOR Descrambling
        descrambledData = reverseMultiThreadedXORDescrambling(from: descrambledData, withKey: key)

        // Reverse AES Scrambling
        if let aesDescrambled = reverseAESScrambling(from: descrambledData, withKey: key) {
            descrambledData = aesDescrambled
        }

        // Reverse Byte Shift
        descrambledData = applyByteShiftScrambling(to: descrambledData, by: -3)

        // Reverse XOR Descrambling
        descrambledData = applyXORScrambling(to: descrambledData, withKey: key)

        return descrambledData
    }

    // MARK: - Scrambling Techniques

    /// Scrambles the data using AES encryption.
    private func applyAESScrambling(to data: Data, withKey key: Data) -> Data? {
        let aesKey = SymmetricKey(data: key.prefix(32)) // Use first 256 bits if longer
        
        do {
            let sealedBox = try AES.GCM.seal(data, using: aesKey)
            return sealedBox.combined // Returning combined ciphertext and authentication tag
        } catch {
            return nil
        }
    }

    /// Descrambles the data using AES decryption.
    private func reverseAESScrambling(from data: Data, withKey key: Data) -> Data? {
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
    private func applyXORScrambling(to data: Data, withKey key: Data) -> Data {
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
    private func applyByteShiftScrambling(to data: Data, by shiftAmount: Int) -> Data {
        var scrambledData = [UInt8](repeating: 0, count: data.count)
        
        // Shift each byte by the specified amount and handle overflows
        for i in 0..<data.count {
            let shiftedValue = (Int(data[i]) + shiftAmount) % 256
            
            // Ensure non-negative results by adjusting modulo for negative shifts
            scrambledData[i] = shiftedValue >= 0 ? UInt8(shiftedValue) : UInt8(shiftedValue + 256)
        }
        
        return Data(scrambledData)
    }

    /// Scrambles the data using multi-threading for faster performance on large datasets.
    private func applyMultiThreadedXORScrambling(to data: Data, withKey key: Data) -> Data {
        var scrambledData = [UInt8](repeating: 0, count: data.count)
        let keyCount = key.count
        let queue = DispatchQueue(label: "com.memoryscrambler.concurrent", attributes: .concurrent)
        let group = DispatchGroup()
        
        let chunkCount = 8 // Number of chunks to split the data into for parallel processing
        let chunkSize = (data.count + chunkCount - 1) / chunkCount // Ensure all bytes are covered
        
        for chunkIndex in 0..<chunkCount {
            queue.async(group: group) {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min((chunkIndex + 1) * chunkSize, data.count)
                
                // Ensure valid range for the last chunk
                guard startIndex < endIndex else { return }
                
                for i in startIndex..<endIndex {
                    let keyIndex = i % keyCount
                    scrambledData[i] = data[i] ^ key[keyIndex]
                }
            }
        }
        
        group.wait() // Wait for all chunks to finish
        return Data(scrambledData)
    }

    /// Descrambles the data using multi-threading (same as scramble, as XOR is symmetric).
    private func reverseMultiThreadedXORDescrambling(from data: Data, withKey key: Data) -> Data {
        return applyMultiThreadedXORScrambling(to: data, withKey: key)
    }
}
