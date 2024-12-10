//
//  CryptographyProtocol.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public protocol CryptographicService {
    
    func encrypt(data: Data, withKey key: Data, iv: Data?, algorithm: CryptoAlgorithm) -> Data?
    func decrypt(data: Data, withKey key: Data, iv: Data?, algorithm: CryptoAlgorithm) -> Data?
    func generateRandomIV(forAlgorithm algorithm: CryptoAlgorithm) -> Data?
    func deriveKey(fromPassword password: String, salt: Data, iterations: Int) -> Data?
    func hmac(data: Data, key: Data) -> Data?
}
