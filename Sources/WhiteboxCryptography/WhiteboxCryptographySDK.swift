//
//  WhiteboxCryptography.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public class WhiteboxCryptographySDK {
    
    private let memoryKey: Data
    private let cryptographicService: CryptographicService
    private let memoryScrambler: MemoryScrambler
    
    public init(memoryKey: Data) {
        self.memoryKey = memoryKey
        self.cryptographicService = CryptographicServiceImpl()
        self.memoryScrambler = MemoryScramblerImpl()
    }
    
    // MARK: - Encrypt Data
    public func encrypt(data: Data, withKey key: Data, iv: Data?, algorithm: CryptoAlgorithm) throws -> Data? {
        try algorithm.validateKeySize(key.count * 8)
        try algorithm.validateIVSize(iv: iv)
        let scrambledData = try memoryScrambler.scramble(data: data, withKey: memoryKey, processingType: algorithm.processingType)
        return try cryptographicService.encrypt(data: scrambledData, withKey: key, iv: iv, algorithm: algorithm)
    }
    
    // MARK: - Decrypt Data
    public func decrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CryptoAlgorithm)throws -> Data? {
        try algorithm.validateKeySize(key.count * 8)
        try algorithm.validateIVSize(iv: iv)
        guard let decryptedData = try cryptographicService.decrypt(data: data, withKey: key, iv: iv, algorithm: algorithm) else {
            throw CryptographicError.decryptionError
        }
        return try memoryScrambler.descramble(data: decryptedData, withKey: memoryKey, processingType: algorithm.processingType)
    }
    
    // MARK: - IV Generation
    public func generateRandomIV(forAlgorithm: CryptoAlgorithm) -> Data? {
        return cryptographicService.generateRandomIV(forAlgorithm: forAlgorithm)
    }
    
    // MARK: - Key Derivation (PBKDF2)
    public func deriveKey(fromPassword password: String, salt: Data, iterations: Int) -> Data? {
        return cryptographicService.deriveKey(fromPassword: password, salt: salt, iterations: iterations)
    }
    
    // MARK: - HMAC Generation
    public func hmac(data: Data, key: Data) -> Data? {
        return cryptographicService.hmac(data: data, key: key)
    }
    
    // MARK: - Key Derivation (PBKDF2)
    public func generateRandomKey(forAlgorithm: CryptoAlgorithm) -> Data? {
        return cryptographicService.generateRandomKey(forAlgorithm: forAlgorithm)
    }
}
