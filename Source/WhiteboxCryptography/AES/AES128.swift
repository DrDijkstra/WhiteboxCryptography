//
//  AES128.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//


import Foundation

class AES128 {
    private static let Nb = 4 // Number of columns in the state (block size = 128 bits)
    private static let Nk = 4 // Number of 32-bit words in the key (128 bits = 4 words)
    private static let Nr = 10 // Number of rounds for AES-128

    var sbox: [UInt8] = []
    var inverseSbox: [UInt8] = []
    var rcon: [UInt8] = []
    private var roundKeys: [UInt8] = []

    init( key: [UInt8]) {
        if let config = readConfig() {
            self.sbox = config.sbox
            self.inverseSbox = config.inverseSbox
            self.rcon = config.rcon
            print("S-box: \(sbox.hexString)")  // Debugging S-box
            print("Inverse S-box: \(inverseSbox.hexString)")  // Debugging inverse S-box
            self.roundKeys = keyExpansion(key)
            
        } else {
            print("Failed to read AES configuration from file.")
        }
    }

    // MARK: - Public Methods

    func encrypt(block: [UInt8]) -> [UInt8] {
        precondition(block.count == AES128.Nb * 4, "Block must be 16 bytes")
        return cipher(block: block)
    }

    func decrypt(block: [UInt8]) -> [UInt8] {
        precondition(block.count == AES128.Nb * 4, "Block must be 16 bytes")
        return inverseCipher(block: block)
    }

    // MARK: - Core AES Functions

    private func cipher(block: [UInt8]) -> [UInt8] {
        var state = blockToState(block)
        addRoundKey(&state, round: 0)

        for round in 1..<AES128.Nr {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, round: round)
        }

        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, round: AES128.Nr)

        return stateToBlock(state)
    }

    private func inverseCipher(block: [UInt8]) -> [UInt8] {
        var state = blockToState(block)
        addRoundKey(&state, round: AES128.Nr)

        for round in stride(from: AES128.Nr - 1, through: 1, by: -1) {
            inverseShiftRows(&state)
            inverseSubBytes(&state)
            addRoundKey(&state, round: round)
            inverseMixColumns(&state)
        }

        inverseShiftRows(&state)
        inverseSubBytes(&state)
        addRoundKey(&state, round: 0)

        return stateToBlock(state)
    }

    // MARK: - State Transformations

    private func subBytes(_ state: inout [[UInt8]]) {
        for row in 0..<4 {
            for col in 0..<AES128.Nb {
                state[row][col] = sbox[Int(state[row][col])]
            }
        }
    }

    private func shiftRows(_ state: inout [[UInt8]]) {
        for row in 1..<4 {
            state[row] = Array(state[row].dropFirst(row) + state[row].prefix(row))
        }
    }

    private func mixColumns(_ state: inout [[UInt8]]) {
        for col in 0..<AES128.Nb {
            let a = state.map { $0[col] }
            state[0][col] = multiply(a[0], 2) ^ multiply(a[1], 3) ^ a[2] ^ a[3]
            state[1][col] = a[0] ^ multiply(a[1], 2) ^ multiply(a[2], 3) ^ a[3]
            state[2][col] = a[0] ^ a[1] ^ multiply(a[2], 2) ^ multiply(a[3], 3)
            state[3][col] = multiply(a[0], 3) ^ a[1] ^ a[2] ^ multiply(a[3], 2)
        }
    }

    private func addRoundKey(_ state: inout [[UInt8]], round: Int) {
        let startIdx = round * AES128.Nb * 4
        for col in 0..<AES128.Nb {
            for row in 0..<4 {
                state[row][col] ^= roundKeys[startIdx + row + 4 * col]
            }
        }
    }

    // MARK: - Inverse Transformations

    private func inverseSubBytes(_ state: inout [[UInt8]]) {
        for row in 0..<4 {
            for col in 0..<AES128.Nb {
                state[row][col] = inverseSbox[Int(state[row][col])]
            }
        }
    }

    private func inverseShiftRows(_ state: inout [[UInt8]]) {
        for row in 1..<4 {
            state[row] = Array(state[row].suffix(row) + state[row].prefix(state[row].count - row))
        }
    }

    private func inverseMixColumns(_ state: inout [[UInt8]]) {
        for col in 0..<AES128.Nb {
            let a = state.map { $0[col] }
            let b = [
                multiply(a[0], 0x0e) ^ multiply(a[1], 0x0b) ^ multiply(a[2], 0x0d) ^ multiply(a[3], 0x09),
                multiply(a[0], 0x09) ^ multiply(a[1], 0x0e) ^ multiply(a[2], 0x0b) ^ multiply(a[3], 0x0d),
                multiply(a[0], 0x0d) ^ multiply(a[1], 0x09) ^ multiply(a[2], 0x0e) ^ multiply(a[3], 0x0b),
                multiply(a[0], 0x0b) ^ multiply(a[1], 0x0d) ^ multiply(a[2], 0x09) ^ multiply(a[3], 0x0e)
            ]
            for row in 0..<4 {
                state[row][col] = b[row]
            }
        }
    }

    // MARK: - Key Expansion

    private func keyExpansion(_ key: [UInt8]) -> [UInt8] {
        var expandedKey = key
        var temp: [UInt8]
        var i = AES128.Nk
        
        print("Initial key expansion: \(expandedKey.hexString)") // Add this line for debugging
        
        while i < AES128.Nb * (AES128.Nr + 1) {
            temp = Array(expandedKey[(i - 1) * 4..<i * 4])
            
            if i % AES128.Nk == 0 {
                temp = xor(subWord(rotWord(temp)), [rcon[i / AES128.Nk - 1], 0, 0, 0])
            }
            
            let previousWord = Array(expandedKey[(i - AES128.Nk) * 4..<i * 4])
            expandedKey.append(contentsOf: xor(previousWord, temp))
            
            i += 1
        }
        print("Expanded keys: \(expandedKey.hexString)") // Add this line for debugging
        return expandedKey
    }




    // MARK: - Utilities

    private func multiply(_ x: UInt8, _ y: UInt8) -> UInt8 {
        var a = x, b = y, result: UInt8 = 0
        while b > 0 {
            if b & 1 != 0 { result ^= a }
            a = (a << 1) ^ ((a & 0x80) != 0 ? 0x1b : 0)
            b >>= 1
        }
        return result
    }

    private func blockToState(_ block: [UInt8]) -> [[UInt8]] {
        var state = Array(repeating: Array(repeating: UInt8(0), count: AES128.Nb), count: 4)
        for i in 0..<block.count {
            state[i % 4][i / 4] = block[i]
        }
        return state
    }

    private func stateToBlock(_ state: [[UInt8]]) -> [UInt8] {
        var block = [UInt8](repeating: 0, count: AES128.Nb * 4)
        for i in 0..<block.count {
            block[i] = state[i % 4][i / 4]
        }
        return block
    }

    private func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        return zip(a, b).map(^)
    }

    private func subWord(_ word: [UInt8]) -> [UInt8] {
        return word.map { sbox[Int($0)] }
    }

    private func rotWord(_ word: [UInt8]) -> [UInt8] {
        return Array(word.dropFirst() + word.prefix(1))
    }
    
    func readConfig() -> (sbox: [UInt8], inverseSbox: [UInt8], rcon: [UInt8])? {
        do {
            let frameworkBundle = Bundle(for: AESServiceImpl.self)
            
            // Ensure the file is found in the bundle using the correct resource name and extension
            guard let fileURL = frameworkBundle.url(forResource: "Sbox_InvSbox_Rcon", withExtension: "txt") else {
                print("File not found")
                return nil
            }
            
            var cnt = 0
            
            // Read the file contents as raw data
            let fileData = try Data(contentsOf: fileURL)
            let cleanedData = Data(
                fileData.enumerated().filter { (index, byte) in
                    if byte == 0x0A && (index - cnt) % 16 == 0  {
                        cnt += 1
                        return false
                    }
                    return true
                }.map { $0.element }
            )
            
            

            var sbox: [UInt8] = []
            var inverseSbox: [UInt8] = []
            var rcon: [UInt8] = []
            
            print("fileData.count \(fileData.count) cleanedData.count \(cleanedData.count)")
            // Start extracting the bytes from the data
            var index = 0
            
            // Read S-box (assuming it's the first 256 bytes)
            sbox = Array(cleanedData[index..<index+256])
            index += 256
            
            // Read Inverse S-box (assuming it's the next 256 bytes)
            inverseSbox = Array(cleanedData[index..<index+256])
            index += 256
            
            // Read Rcon (assuming it's the next 10 bytes)
            rcon = Array(cleanedData[index..<index+10])
            
            return (sbox, inverseSbox, rcon)
            
        } catch {
            print("Error reading file: \(error)")
            return nil
        }
    }
}
