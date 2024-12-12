//
//  AES.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//


import Foundation

class AESCore {
    private var Nb: Int  // Number of columns (fixed at 4 for AES)
    private var Nk: Int  // Number of 32-bit words in the key
    private var Nr: Int  // Number of rounds
    var sbox: [UInt8] = []
    var inverseSbox: [UInt8] = []
    var rcon: [UInt8] = []
    private var roundKeys: [UInt8] = []

    init(key: [UInt8]) {
        let keyType = AESKeySize(rawValue: key.count)
        switch keyType {
        case .bits128:  // AES-128
            Nk = 4
            Nr = 10
        case .bits192:  // AES-192
            Nk = 6
            Nr = 12
        case .bits256:  // AES-256
            Nk = 8
            Nr = 14
        default:
            fatalError("Invalid key size. Key must be 16, 24, or 32 bytes.")
        }
        
        self.Nb = 4  // Fixed for AES
        if let config = readConfig() {
            self.sbox = config.sbox
            self.inverseSbox = config.inverseSbox
            self.rcon = config.rcon
            self.roundKeys = keyExpansion(key)
        } else {
            print("Failed to read AES configuration from file.")
        }
    }

    func encrypt(block: [UInt8]) -> [UInt8] {
        precondition(block.count == Nb * 4, "Block must be 16 bytes")
        return cipher(block: block)
    }

    func decrypt(block: [UInt8]) -> [UInt8] {
        precondition(block.count == Nb * 4, "Block must be 16 bytes")
        return inverseCipher(block: block)
    }

    // MARK: - Core AES Functions

    private func cipher(block: [UInt8]) -> [UInt8] {
        var state = blockToState(block)
        addRoundKey(&state, round: 0)

        for round in 1..<Nr {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, round: round)
        }

        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, round: Nr)

        return stateToBlock(state)
    }

    private func inverseCipher(block: [UInt8]) -> [UInt8] {
        var state = blockToState(block)
        addRoundKey(&state, round: Nr)

        for round in stride(from: Nr - 1, through: 1, by: -1) {
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
            for col in 0..<Nb {
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
        for col in 0..<Nb {
            let a = state.map { $0[col] }
            state[0][col] = multiply(a[0], 2) ^ multiply(a[1], 3) ^ a[2] ^ a[3]
            state[1][col] = a[0] ^ multiply(a[1], 2) ^ multiply(a[2], 3) ^ a[3]
            state[2][col] = a[0] ^ a[1] ^ multiply(a[2], 2) ^ multiply(a[3], 3)
            state[3][col] = multiply(a[0], 3) ^ a[1] ^ a[2] ^ multiply(a[3], 2)
        }
    }

    private func addRoundKey(_ state: inout [[UInt8]], round: Int) {
        let startIdx = round * Nb * 4
        for col in 0..<Nb {
            for row in 0..<4 {
                state[row][col] ^= roundKeys[startIdx + row + 4 * col]
            }
        }
    }

    // MARK: - Inverse Transformations

    private func inverseSubBytes(_ state: inout [[UInt8]]) {
        for row in 0..<4 {
            for col in 0..<Nb {
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
        for col in 0..<Nb {
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
        var i = Nk
                
        while i < Nb * (Nr + 1) {
            temp = Array(expandedKey[(i - 1) * 4..<i * 4])
            
            if i % Nk == 0 {
                temp = xor(subWord(rotWord(temp)), [rcon[i / Nk - 1], 0, 0, 0])
            }
            
            let previousWord = Array(expandedKey[(i - Nk) * 4..<i * 4])
            expandedKey.append(contentsOf: xor(previousWord, temp))
            
            i += 1
        }
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
        var state = Array(repeating: Array(repeating: UInt8(0), count: Nb), count: 4)
        for i in 0..<block.count {
            state[i % 4][i / 4] = block[i]
        }
        return state
    }

    private func stateToBlock(_ state: [[UInt8]]) -> [UInt8] {
        var block = [UInt8](repeating: 0, count: Nb * 4)
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
    
    func encryptData(data: [UInt8], iv: [UInt8]) -> [UInt8] {
        let blockSize = Nb * 4 // 16 bytes
        var ciphertext: [UInt8] = []
        var previousBlock = iv

        // Pad the data if it's not a multiple of block size
        var dataToEncrypt = data
        if dataToEncrypt.count % blockSize != 0 {
            dataToEncrypt = pad(dataToEncrypt) // Padding data
        } else {
            // If data length is exactly a multiple of block size, pad anyway (using 0x10 as padding byte value)
            dataToEncrypt = pad(dataToEncrypt)
        }

        for i in stride(from: 0, to: dataToEncrypt.count, by: blockSize) {
            let block = Array(dataToEncrypt[i..<min(i + blockSize, dataToEncrypt.count)])
            let blockToEncrypt = xorBlocks(block, previousBlock)
            let encryptedBlock = encrypt(block: blockToEncrypt)
            ciphertext.append(contentsOf: encryptedBlock)
            previousBlock = encryptedBlock
        }

        return ciphertext
    }

    private func pad(_ block: [UInt8]) -> [UInt8] {
        let paddingLength = Nb * 4 - (block.count % (Nb * 4)) // Calculate padding required for next 16-byte boundary
        
        // If the block is already a multiple of 16 bytes, add 16 bytes of padding (using 0x10 as padding value)
        let actualPaddingLength = paddingLength == 0 ? Nb * 4 : paddingLength
        let padding = [UInt8](repeating: UInt8(actualPaddingLength), count: actualPaddingLength)
        
        return block + padding
    }

    func decryptData(data: [UInt8], iv: [UInt8]) -> [UInt8] {
        let blockSize = Nb * 4 // 16 bytes
        var plaintext: [UInt8] = []
        var previousBlock = iv

        for i in stride(from: 0, to: data.count, by: blockSize) {
            let block = Array(data[i..<min(i + blockSize, data.count)])
            let decryptedBlock = decrypt(block: block)
            let decryptedXorBlock = xorBlocks(decryptedBlock, previousBlock)
            plaintext.append(contentsOf: decryptedXorBlock)
            previousBlock = block
        }

        return unpad(plaintext) // Call unpad to remove the padding after decryption
    }

    private func unpad(_ block: [UInt8]) -> [UInt8] {
        // Unpadding should remove the padding bytes (last byte value tells how much to remove)
        guard let paddingValue = block.last else { return block }
        
        // Remove the padding based on the last byte value
        let paddingLength = Int(paddingValue)
        
        // Ensure that we don't remove too much
        return Array(block.dropLast(paddingLength))
    }



    private func xorBlocks(_ block1: [UInt8], _ block2: [UInt8]) -> [UInt8] {
        // XOR each byte of two blocks
        return zip(block1, block2).map { $0 ^ $1 }
    }
        
    func readConfig() -> (sbox: [UInt8], inverseSbox: [UInt8], rcon: [UInt8])? {
       
        let frameworkBundle = Bundle(for: AESServiceImpl.self)
        
        // Ensure the file is found in the bundle using the correct resource name and extension
        guard let fileURL = frameworkBundle.url(forResource: "Sbox_InvSbox_Rcon", withExtension: "txt") else {
            print("File not found")
            return nil
        }
        
        guard let fileData = try? Data(contentsOf: fileURL) else {
               print("Error: Could not read file at path \(fileURL.path)")
               return nil
           }

       let totalSize = fileData.count
       if totalSize < 256 + 256 + 10 {
           print("Error: File does not contain enough data.")
           return nil
       }

        // Extract S-box, Inverse S-box, and Rcon
        let sbox = Array(fileData[0..<256])
        let inverseSbox = Array(fileData[256..<512])
        let rcon = Array(fileData[512..<522])
        
        return (sbox, inverseSbox, rcon)
            
        
    }
}
