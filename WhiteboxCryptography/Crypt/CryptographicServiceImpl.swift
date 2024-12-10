//
//  CryptographicService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto
import CryptoKit

public class CryptographicServiceImpl: CryptographicService {
    
    // MARK: - Cryptographic operation (encryption or decryption)
    public func crypt(data: Data, key: Data, iv: Data?, operation: Int, algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)) -> Data? {
        _ = [UInt8](key)
        _ = [UInt8](data)
        var result = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var resultLength = 0
        
        let ivPointer = iv?.withUnsafeBytes { $0.baseAddress } ?? nil
        
        let status = key.withUnsafeBytes { keyPointer in
            data.withUnsafeBytes { dataPointer in
                CCCrypt(
                    CCOperation(operation),
                    algorithm,
                    CCOptions(kCCOptionPKCS7Padding),
                    keyPointer.baseAddress, kCCKeySizeAES256,
                    ivPointer, // IV for CBC, can be nil for ECB
                    dataPointer.baseAddress, data.count,
                    &result, result.count,
                    &resultLength
                )
            }
        }
        
        guard status == kCCSuccess else {
            print("Cryptographic operation failed with status: \(status)")
            return nil
        }
        
        return Data(result.prefix(resultLength))
    }
    
    // MARK: - AES Encryption with IV (CBC or GCM)
    public func encrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)) -> Data? {
        return crypt(data: data, key: key, iv: iv, operation: kCCEncrypt, algorithm: algorithm)
    }
    
    // MARK: - AES Decryption with IV (CBC or GCM)
    public func decrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)) -> Data? {
        return crypt(data: data, key: key, iv: iv, operation: kCCDecrypt, algorithm: algorithm)
    }
    
    // MARK: - Generate Random Initialization Vector (IV) for AES CBC or GCM
    public func generateRandomIV(forAlgorithm algorithm: CryptoAlgorithm) -> Data? {
       
        
        // Generate random IV of the determined size
        var iv = Data(count: algorithm.ivSize)
        let result = iv.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, algorithm.ivSize, bytes.baseAddress!)
        }
        
        return result == errSecSuccess ? iv : nil
    }

    
    // MARK: - Key Derivation using PBKDF2
    public func deriveKey(fromPassword password: String, salt: Data, iterations: Int = 10000) -> Data? {
        let keyLength = kCCKeySizeAES256 // 32 bytes for AES-256
        var derivedKey = Data(repeating: 0, count: keyLength)

        let passwordData = password.data(using: .utf8) ?? Data()
        
        let status = derivedKey.withUnsafeMutableBytes { derivedKeyPointer in
            salt.withUnsafeBytes { saltPointer in
                passwordData.withUnsafeBytes { passwordPointer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPointer.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltPointer.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyPointer.baseAddress,
                        keyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            print("Key derivation failed with status: \(status)")
            return nil
        }

        return derivedKey
    }

    
    // MARK: - HMAC for Integrity Checking
    public func hmac(data: Data, key: Data) -> Data? {
        var result = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        key.withUnsafeBytes { keyPointer in
            data.withUnsafeBytes { dataPointer in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    keyPointer.baseAddress, key.count,
                    dataPointer.baseAddress, data.count,
                    &result
                )
            }
        }
        
        return Data(result)
    }
    
    // MARK: - AES GCM Encryption/Decryption (Authenticated Encryption) - Using CryptoKit
    public func encryptGCM(data: Data, withKey key: Data, iv: Data) -> Data? {
        guard key.count == 32 else {
            print("Invalid key size: \(key.count). Key must be 32 bytes for AES256.")
            return nil
        }
        guard iv.count == 12 else {
            print("Invalid IV size: \(iv.count). IV must be 12 bytes for AES-GCM.")
            return nil
        }

        let symmetricKey = SymmetricKey(data: key)

        do {
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: AES.GCM.Nonce(data: iv))
            return sealedBox.combined
        } catch {
            print("GCM encryption failed: \(error.localizedDescription)")
            return nil
        }
    }

    
    public func decryptGCM(data: Data, withKey key: Data, iv: Data) -> Data? {
        let symmetricKey = SymmetricKey(data: key)
        
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: Data())
            return decryptedData
        } catch {
            print("GCM decryption failed: \(error)")
            return nil
        }
    }
}
