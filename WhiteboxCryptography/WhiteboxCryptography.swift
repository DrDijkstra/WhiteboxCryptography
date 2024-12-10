//
//  WhiteboxCryptography.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation


import Foundation

public class WhiteboxCryptography {
    
    private let memoryKey: Data
    private let cryptographicService: CryptographicService
    private let memoryScrambler: MemoryScrambler

    public init(memoryKey: Data) {
        self.memoryKey = memoryKey
        self.cryptographicService = CryptographicServiceImpl()
        self.memoryScrambler = MemoryScramblerImpl()
    }
    
    // MARK: - CryptographyProtocol Implementation
    public func encrypt(data: Data, withKey key: Data) -> Data? {
        // First scramble the data
        let scrambledData = memoryScrambler.scramble(data: data, withKey: memoryKey)
        // Then perform encryption using CryptographicService
        return cryptographicService.encrypt(data: scrambledData, withKey: key)
    }
    
    public func decrypt(data: Data, withKey key: Data) -> Data? {
        // Perform decryption using CryptographicService
        guard let decryptedData = cryptographicService.decrypt(data: data, withKey: key) else {
            return nil
        }
        // Then descramble the data
        return memoryScrambler.descramble(data: decryptedData, withKey: memoryKey)
    }
}
