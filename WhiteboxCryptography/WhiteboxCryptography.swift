//
//  WhiteboxCryptography.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public class WhiteboxCryptography {
    
    private let memoryKey: Data
    private let cryptographicService: CryptographicService
    private let memoryScrambler: MemoryScrambler
    
    // Initialize with memory key, cryptographic service, and memory scrambler
    public init(memoryKey: Data) {
        self.memoryKey = memoryKey
        self.cryptographicService = CryptographicServiceImpl() // Using the implementation of CryptographicService
        self.memoryScrambler = MemoryScramblerImpl() // Assuming MemoryScramblerImpl is defined elsewhere
    }
    
    // MARK: - Encrypt Data
    public func encrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)) -> Data? {
        // First scramble the data using the memory key
        let scrambledData = memoryScrambler.scramble(data: data, withKey: memoryKey)
        
        // Perform encryption using CryptographicService (CBC, GCM, etc.)
        return cryptographicService.encrypt(data: scrambledData, withKey: key, iv: iv, algorithm: algorithm)
    }
    
    // MARK: - Decrypt Data
    public func decrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)) -> Data? {
        // Decrypt the data using CryptographicService
        guard let decryptedData = cryptographicService.decrypt(data: data, withKey: key, iv: iv, algorithm: algorithm) else {
            return nil
        }
        
        // Then descramble the decrypted data using the memory key
        return memoryScrambler.descramble(data: decryptedData, withKey: memoryKey)
    }
    
    // MARK: - IV Generation
    public func generateRandomIV() -> Data? {
        return cryptographicService.generateRandomIV()
    }
    
    // MARK: - Key Derivation (PBKDF2)
    public func deriveKey(fromPassword password: String, salt: Data, iterations: Int) -> Data? {
        return cryptographicService.deriveKey(fromPassword: password, salt: salt, iterations: iterations)
    }
    
    // MARK: - HMAC Generation
    public func hmac(data: Data, key: Data) -> Data? {
        return cryptographicService.hmac(data: data, key: key)
    }
    
    // MARK: - AES GCM Encryption
    public func encryptGCM(data: Data, withKey key: Data, iv: Data) -> Data? {
        return cryptographicService.encryptGCM(data: data, withKey: key, iv: iv)
    }
    
    // MARK: - AES GCM Decryption
    public func decryptGCM(data: Data, withKey key: Data, iv: Data) -> Data? {
        return cryptographicService.decryptGCM(data: data, withKey: key, iv: iv)
    }
}
