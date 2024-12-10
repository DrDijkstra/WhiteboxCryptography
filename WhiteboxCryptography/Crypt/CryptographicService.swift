//
//  CryptographyProtocol.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public protocol CryptographicService {
    
    // Encrypt data using AES (with optional IV for CBC/GCM modes)
    func encrypt(data: Data, withKey key: Data, iv: Data?, algorithm: CCAlgorithm) -> Data?
    
    // Decrypt data using AES (with optional IV for CBC/GCM modes)
    func decrypt(data: Data, withKey key: Data, iv: Data?, algorithm: CCAlgorithm) -> Data?
    
    // Generate random Initialization Vector (IV) for AES CBC or GCM
    func generateRandomIV(forAlgorithm algorithm: CryptoAlgorithm) -> Data?
    
    // Derive key using PBKDF2 from a password
    func deriveKey(fromPassword password: String, salt: Data, iterations: Int) -> Data?
    
    // Generate HMAC for integrity verification
    func hmac(data: Data, key: Data) -> Data?
    
    // AES GCM Encryption (Authenticated Encryption)
    func encryptGCM(data: Data, withKey key: Data, iv: Data) -> Data?
    
    // AES GCM Decryption (Authenticated Decryption)
    func decryptGCM(data: Data, withKey key: Data, iv: Data) -> Data?
}
