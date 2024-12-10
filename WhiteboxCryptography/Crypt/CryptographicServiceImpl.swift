//
//  CryptographicService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//


import Foundation
import CommonCrypto

public class CryptographicServiceImpl:CryptographicService  {
    
    // Perform cryptographic operation (encryption or decryption)
    public func crypt(data: Data, key: Data, operation: Int) -> Data? {
        var keyBytes = [UInt8](key)
        var dataBytes = [UInt8](data)
        var result = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var resultLength = 0
        
        let status = key.withUnsafeBytes { keyPointer in
            data.withUnsafeBytes { dataPointer in
                CCCrypt(
                    CCOperation(operation),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),
                    keyPointer.baseAddress, kCCKeySizeAES256,
                    nil, // IV (can be added as needed)
                    dataPointer.baseAddress, data.count,
                    &result, result.count,
                    &resultLength
                )
            }
        }
        
        guard status == kCCSuccess else { return nil }
        
        return Data(result.prefix(resultLength))
    }
    
    // Encrypt data using AES
    public func encrypt(data: Data, withKey key: Data) -> Data? {
        return crypt(data: data, key: key, operation: kCCEncrypt)
    }
    
    // Decrypt data using AES
    public  func decrypt(data: Data, withKey key: Data) -> Data? {
        return crypt(data: data, key: key, operation: kCCDecrypt)
    }
}
