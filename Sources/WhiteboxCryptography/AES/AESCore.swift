//
//  AES.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//


import Foundation

public class AESCore {
    private var Nb: Int = 4 // Number of columns (fixed at 4 for AES)
    private var Nk: Int = 4 // Number of 32-bit words in the key
    private var Nr: Int = 10 // Number of rounds
    var sbox: [UInt8] = []
    var inverseSbox: [UInt8] = []
    var rcon: [UInt8] = []
    private var roundKeys: [UInt8] = []
    var mode: AESMode = .ecb

    public init() {
        if let config = readConfig() {
            self.sbox = config.sbox
            self.inverseSbox = config.inverseSbox
            self.rcon = config.rcon
        }else{
            fatalError("File not found")
        }
    }
    
    /// Updates the encryption keys and mode.
    public func update(key: [UInt8], mode: AESMode) throws {
        // Determine key size and number of rounds
        let keySize = key.count
        guard let keyType = AESKeySize(rawValue: keySize) else {
            throw CryptographicError.invalidKeySize
        }

        switch keyType {
        case .bits128:
            self.Nk = 4
            self.Nr = 10
        case .bits192:
            self.Nk = 6
            self.Nr = 12
        case .bits256:
            self.Nk = 8
            self.Nr = 14
        }
        

        // Perform key expansion to generate round keys
        self.roundKeys = keyExpansion(key)
        self.mode = mode
    }

    public func encryptData(data: [UInt8], iv: [UInt8] = []) throws -> [UInt8] {
        switch mode {
        case .ecb:
            return try ecbEncrypt(data: data)
        case .cbc:
            return try cbcEncrypt(data: data, iv: iv)
        case .gcm:
            return try gcmEncrypt(data: data, iv: iv)
        }
    }

    public func decryptData(data: [UInt8], iv: [UInt8] = []) throws -> [UInt8]? {
        switch mode {
        case .ecb:
            return try ecbDecrypt(data: data)
        case .cbc:
            return try cbcDecrypt(data: data, iv: iv)
        case .gcm:
            return try gcmDecrypt(data: data, iv: iv)
        }
    }
    
    private func encrypt(block: [UInt8]) throws -> [UInt8] {
        guard block.count == Nb * 4 else {
            throw CryptographicError.invalidBlockSize
        }
        return cipher(block: block)
    }

    private func decrypt(block: [UInt8]) throws -> [UInt8] {
        guard block.count == Nb * 4 else {
            throw CryptographicError.invalidBlockSize
        }
        return inverseCipher(block: block)
    }

    private func ecbEncrypt(data: [UInt8]) throws -> [UInt8] {
        let blockSize = Nb * 4  // AES block size (16 bytes)
        var ciphertext: [UInt8] = []
        
        // Pad data to a multiple of block size
        let paddedData = pad(data)
        
        // Encrypt each block
        for i in stride(from: 0, to: paddedData.count, by: blockSize) {
            let block = Array(paddedData[i..<min(i + blockSize, paddedData.count)])
            let encryptedBlock = try encrypt(block: block)
            ciphertext.append(contentsOf: encryptedBlock)
        }

        return ciphertext
    }

    private func ecbDecrypt(data: [UInt8]) throws -> [UInt8] {
        let blockSize = Nb * 4  // AES block size (16 bytes)
        var plaintext: [UInt8] = []

        // Decrypt each block
        for i in stride(from: 0, to: data.count, by: blockSize) {
            let block = Array(data[i..<min(i + blockSize, data.count)])
            let decryptedBlock = try decrypt(block: block)
            plaintext.append(contentsOf: decryptedBlock)
        }

        // Remove padding
        return try unpad(plaintext)
    }

    private func cbcEncrypt(data: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        let blockSize = Nb * 4  // Typically 16 bytes for AES (128 bits).
        var ciphertext: [UInt8] = []
        var previousBlock = iv

        var dataToEncrypt = data
        dataToEncrypt = pad(dataToEncrypt)

        for i in stride(from: 0, to: dataToEncrypt.count, by: blockSize) {
            let block = Array(dataToEncrypt[i..<min(i + blockSize, dataToEncrypt.count)])
            let blockToEncrypt = xorBlocks(block, previousBlock)
            let encryptedBlock = try encrypt(block: blockToEncrypt)
            ciphertext.append(contentsOf: encryptedBlock)
            previousBlock = encryptedBlock
        }

        return ciphertext
    }


    private func cbcDecrypt(data: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard iv.count == 16 else {
            throw CryptographicError.invalidIVSize
        }
        let blockSize = Nb * 4
        var plaintext: [UInt8] = []
        var previousBlock = iv

        for i in stride(from: 0, to: data.count, by: blockSize) {
            let block = Array(data[i..<min(i + blockSize, data.count)])
            let decryptedBlock = try decrypt(block: block)
            let decryptedXorBlock = xorBlocks(decryptedBlock, previousBlock)
            plaintext.append(contentsOf: decryptedXorBlock)
            previousBlock = block
        }

        // Remove padding after decryption
        return try unpad(plaintext)
    }

    private func gcmEncrypt(data: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard iv.count == 12 else {
            throw CryptographicError.invalidIVSize
        }

        let blockSize = Nb * 4

        // Set up the counter block using the IV as the base counter
        var counterBlock = iv
        counterBlock.append(contentsOf: [0, 0, 0, 1])  // Start with counter value = 1
        var counter = counterBlock
        var cipherBlock: [UInt8]
        var encryptedText: [UInt8] = []

        for i in stride(from: 0, to: data.count, by: blockSize) {
            let block = Array(data[i..<min(i + blockSize, data.count)])
            cipherBlock = try encryptCounterBlock(counter)
            let encryptedBlock = xorBlocks(block, cipherBlock)
            encryptedText.append(contentsOf: encryptedBlock)
            counter = incrementCounter(counter)
        }

        // Compute a checksum of the IV as the tag
        let tag = computeChecksum(from: iv)

        // IV will be appended along with the checksum tag to the ciphertext
        return encryptedText + tag
    }

    // Helper function to compute a checksum from the IV
    private func computeChecksum(from data: [UInt8]) -> [UInt8] {
        var checksum = UInt32(0)
        for byte in data {
            checksum = checksum ^ UInt32(byte)  // XOR each byte into checksum
        }

        // Convert checksum into 4 bytes (32-bit checksum)
        return withUnsafeBytes(of: &checksum) { Array($0) }
    }


    private func gcmDecrypt(data: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard iv.count == 12 else {
            throw CryptographicError.invalidIVSize
        }

        let blockSize = Nb * 4
        let tagLength = 4  // Checksum tag is 4 bytes

        // Separate ciphertext (excluding the tag portion) from input data
        let ciphertext = Array(data[0..<data.count - tagLength])

        // Extract the checksum tag from the last 4 bytes of the data
        let receivedTag = Array(data.suffix(tagLength))

        // Compute the checksum of the IV and compare it to the received tag
        let computedTag = computeChecksum(from: iv)

        // Validate the checksum
        if computedTag != receivedTag {
            throw CryptographicError.authenticationFailed
        }

        // Counter block setup: The IV is used as the base for the counter.
        var counterBlock = iv
        counterBlock.append(contentsOf: [0, 0, 0, 1])  // Start with counter value = 1
        var counter = counterBlock
        var cipherBlock: [UInt8]
        var decryptedText: [UInt8] = []

        for i in stride(from: 0, to: ciphertext.count, by: blockSize) {
            let block = Array(ciphertext[i..<min(i + blockSize, ciphertext.count)])
            cipherBlock = try encryptCounterBlock(counter)
            let decryptedBlock = xorBlocks(block, cipherBlock)
            decryptedText.append(contentsOf: decryptedBlock)
            counter = incrementCounter(counter)
        }

        return decryptedText
    }

    // Helper Methods

    private func xorBlocks(_ block1: [UInt8], _ block2: [UInt8]) -> [UInt8] {
        return zip(block1, block2).map { $0 ^ $1 }
    }

    private func pad(_ data: [UInt8]) -> [UInt8] {
        let blockSize = 16
        let paddingLength = blockSize - (data.count % blockSize)
        
        // If padding length is 0 (i.e., data is a multiple of block size), add a full block of padding
        let paddingValue: UInt8 = paddingLength == 0 ? UInt8(blockSize) : UInt8(paddingLength)
        
        // Create random padding for all bytes except the last one
        var padding = [UInt8]()
        
        for _ in 0..<paddingLength-1 {
            padding.append(UInt8.random(in: 0...255)) // Random padding
        }
        
        // Add the padding length in the last byte
        padding.append(paddingValue)
        
        return data + padding
    }

    private func unpad(_ data: [UInt8]) throws -> [UInt8] {
        guard let paddingLength = data.last else {
            throw CryptographicError.paddingError
        }
        
        // Check that the padding length is valid
        if paddingLength > 16 || paddingLength == 0 {
            throw CryptographicError.paddingError
        }
        
        // Remove the padding by dropping the last `paddingLength` bytes
        let unpaddedData = data.dropLast(Int(paddingLength))
        return Array(unpaddedData)
    }


    private func incrementCounter(_ counter: [UInt8]) -> [UInt8] {
        var newCounter = counter
        var carry = true
        for i in (0..<counter.count).reversed() {
            if carry {
                newCounter[i] += 1
                carry = newCounter[i] == 0
            }
        }
        return newCounter
    }

    private func encryptCounterBlock(_ counter: [UInt8]) throws -> [UInt8] {
        return try encrypt(block: counter)
    }

    private func computeGCMTag(data: [UInt8], iv: [UInt8], totalLength: Int) -> [UInt8] {
        /// Create the GCM polynomial and initialize variables for authentication
        var H: [UInt8] = [UInt8](repeating: 0, count: 16) // H is the AES block size (16 bytes)
        var GCMTag: [UInt8] = [UInt8](repeating: 0, count: 16) // Authentication tag (16 bytes)
        
        /// Step 1: Compute the H value (AES block cipher output of zero block)
        let zeroBlock: [UInt8] = [UInt8](repeating: 0, count: 16)
        let zeroBlockCipher = cipher(block: zeroBlock)
        H = zeroBlockCipher
        
        /// Step 2: XOR the data with the H value for authentication (simulates GHASH)
        var X: [UInt8] = [UInt8](repeating: 0, count: 16) // Accumulator for GHASH
        
        for i in stride(from: 0, to: data.count, by: 16) {
            let block = Array(data[i..<min(i + 16, data.count)])
            X = xorBlocks(X, block)
            X = ghash(X, H)
        }
        
        /// Step 3: Include the length of the data in the authentication process
        var lenBlock: [UInt8] = [UInt8](repeating: 0, count: 16)
        let len = totalLength * 8 // Length in bits
        lenBlock[0] = UInt8((len >> 56) & 0xFF)
        lenBlock[1] = UInt8((len >> 48) & 0xFF)
        lenBlock[2] = UInt8((len >> 40) & 0xFF)
        lenBlock[3] = UInt8((len >> 32) & 0xFF)
        lenBlock[4] = UInt8((len >> 24) & 0xFF)
        lenBlock[5] = UInt8((len >> 16) & 0xFF)
        lenBlock[6] = UInt8((len >> 8) & 0xFF)
        lenBlock[7] = UInt8(len & 0xFF)

        X = xorBlocks(X, lenBlock)
        
        /// Step 4: Final GCM tag computation
        GCMTag = ghash(X, H)

        return GCMTag
    }
    
    private func ghash(_ data: [UInt8], _ H: [UInt8]) -> [UInt8] {
        let X = data
        var result = [UInt8](repeating: 0, count: 16)
        
        // Perform XOR with the H block and return the result
        for i in 0..<16 {
            result[i] = X[i] ^ H[i]
        }
        
        return result
    }


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
    
    func readConfig() -> (sbox: [UInt8], inverseSbox: [UInt8], rcon: [UInt8])? {
       
        let bundle: Bundle

        // Check if we're using SPM
        #if SWIFT_PACKAGE
            // For SPM (Swift Package Manager)
            bundle = Bundle.module
        #else
            // For CocoaPods
            bundle = Bundle(for: type(of: self))
        #endif
        
        
        guard let fileURL = bundle.url(forResource: "Sbox_InvSbox_Rcon", withExtension: "txt") else {
                print("File not found in the bundle")
                return nil
            }
        
        // Ensure the file is found in the bundle using the correct resource name and extension
//        guard let fileURL = frameworkBundle.url(forResource: "Sbox_InvSbox_Rcon", withExtension: "txt") else {
//            print("File not found")
//            return nil
//        }
        
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
    
    private func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        return zip(a, b).map(^)
    }
    
    private func subWord(_ word: [UInt8]) -> [UInt8] {
        return word.map { sbox[Int($0)] }
    }

    private func rotWord(_ word: [UInt8]) -> [UInt8] {
        return Array(word.dropFirst() + word.prefix(1))
    }
    
    private func blockToState(_ block: [UInt8]) -> [[UInt8]] {
        var state = Array(repeating: Array(repeating: UInt8(0), count: Nb), count: 4)
        for i in 0..<block.count {
            state[i % 4][i / 4] = block[i]
        }
        return state
    }
    
    private func addRoundKey(_ state: inout [[UInt8]], round: Int) {
        let startIdx = round * Nb * 4
        for col in 0..<Nb {
            for row in 0..<4 {
                state[row][col] ^= roundKeys[startIdx + row + 4 * col]
            }
        }
    }
    
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
    
    private func multiply(_ x: UInt8, _ y: UInt8) -> UInt8 {
        var a = x, b = y, result: UInt8 = 0
        while b > 0 {
            if b & 1 != 0 { result ^= a }
            a = (a << 1) ^ ((a & 0x80) != 0 ? 0x1b : 0)
            b >>= 1
        }
        return result
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
    
    private func stateToBlock(_ state: [[UInt8]]) -> [UInt8] {
        var block = [UInt8](repeating: 0, count: Nb * 4)
        for i in 0..<block.count {
            block[i] = state[i % 4][i / 4]
        }
        return block
    }
    
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

}
