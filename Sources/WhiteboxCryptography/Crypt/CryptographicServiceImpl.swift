//
//  CryptographicService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto
import CryptoKit

// MARK: - Cryptographic Service Implementation
public class CryptographicServiceImpl: CryptographicService {
    
    public var aesService: AESService
    
    public init(aesService: AESService = AESServiceImpl()) {
        self.aesService = aesService
    }

    // MARK: - Cryptographic operation (encryption or decryption)
    private func crypt(data: Data, key: Data, iv: Data?, operation: Int, algorithm: CryptoAlgorithm) throws -> Data? {
            switch algorithm {
            case .aes(let keysize, let mode, let processingType):
                switch processingType {
                case .faster:
                    switch mode {
                    case .cbc:
                        return try doNativeEncryption(data: data, key: key, iv: iv, operation: operation, algorithm: algorithm)
                    case .gcm:
                        switch  AESKeySize(rawValue: keysize / 8) {
                        case .bits256:
                            return gcmEncryptDecrypt(data: data, key: key, iv: iv, operation: operation)
                        default:
                            throw CryptographicError.fasterGCMisNotAvailableForKeySize192And128
                        }
                       
                    case .ecb:
                        throw CryptographicError.ecbNotAvailableInFasterProcessingType
                    }
                case .regular:
                    return try aesServiceCrypt(data: data, key: key, iv: iv, operation: operation, mode: mode)
                }
               
            default:
                return try doNativeEncryption(data: data, key: key, iv: iv, operation: operation, algorithm: algorithm)
            }
        }
    
    func doNativeEncryption(data: Data, key: Data, iv: Data?, operation: Int, algorithm: CryptoAlgorithm) throws -> Data {
        
        
        // Select the correct algorithm
        let cryptoAlgorithm: UInt32
        let blockSize: Int
        
        cryptoAlgorithm = algorithm.ccAlgorithm
        blockSize = algorithm.ivSize
        
        // Prepare a buffer for the result
        let resultSize = data.count + blockSize
        var result = [UInt8](repeating: 0, count: resultSize)
        var resultLength: size_t = 0
        
        // Perform the cryptographic operation
        var status: CCCryptorStatus = -1

        // Access the data's buffer
        data.withUnsafeBytes { inputBytes in
            key.withUnsafeBytes { keyBytes in
                if let iv = iv {
                    // If IV exists
                    iv.withUnsafeBytes { ivBytes in
                        // Perform the cryptographic operation
                        result.withUnsafeMutableBytes { resultBytes in
                            status = CCCrypt(
                                CCOperation(operation),
                                cryptoAlgorithm,
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, key.count,
                                ivBytes.baseAddress,
                                inputBytes.baseAddress, data.count,
                                resultBytes.baseAddress, resultSize,
                                &resultLength
                            )
                        }
                    }
                } else {
                    // If IV is nil
                    result.withUnsafeMutableBytes { resultBytes in
                        status = CCCrypt(
                            CCOperation(operation),
                            CCAlgorithm(cryptoAlgorithm),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count,
                            nil,  // No IV
                            inputBytes.baseAddress, data.count,
                            resultBytes.baseAddress, resultSize,
                            &resultLength
                        )
                    }
                }
            }
        }

        // Check the operation status
        guard status == kCCSuccess else {
            throw CryptographicError.cryptOperationFailed(status: Int(status))
        }
        
        // Return the result data up to the actual length
        return Data(result.prefix(resultLength))
    }


    // MARK: - AES encryption/decryption
    private func aesServiceCrypt(data: Data, key: Data, iv: Data?, operation: Int, mode: AESMode) throws -> Data? {
        switch operation {
        case kCCEncrypt:
            return try aesService.encrypt(block: data, key: key, iv: iv, mode: mode)
        case kCCDecrypt:
            return try aesService.decrypt(block: data, key: key, iv: iv, mode: mode)
        default:
            return nil
        }
    }

    // MARK: - AES Encryption with IV (CBC or GCM)
    public func encrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CryptoAlgorithm) throws -> Data? {
        return try crypt(data: data, key: key, iv: iv, operation: kCCEncrypt, algorithm: algorithm)
    }

    // MARK: - AES Decryption with IV (CBC or GCM)
    public func decrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CryptoAlgorithm) throws -> Data? {
        return try crypt(data: data, key: key, iv: iv, operation: kCCDecrypt, algorithm: algorithm)
    }

    // MARK: - Generate Random Key for Specified Algorithm
    public func generateRandomKey(forAlgorithm algorithm: CryptoAlgorithm) -> Data? {
        var keySizeInBits: Int?

        for validSize in algorithm.validKeySizes {
            if case .specific(let keySize) = validSize {
                keySizeInBits = keySize
                break
            } else if case .range(let min, let max) = validSize {
                keySizeInBits = Int.random(in: min...max)
                break
            }
        }

        guard let keySize = keySizeInBits else {
            return nil
        }

        let keySizeInBytes = keySize / 8

        return generateRandomData(ofLength: keySizeInBytes)
    }

    // MARK: - Generate Random IV
    public func generateRandomIV(forAlgorithm algorithm: CryptoAlgorithm) -> Data? {
        return generateRandomData(ofLength: algorithm.ivSize)
    }

    private func generateRandomData(ofLength length: Int) -> Data? {
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, length, bytes.baseAddress!)
        }
        return result == errSecSuccess ? data : nil
    }

    // MARK: - Key Derivation using PBKDF2
    public func deriveKey(fromPassword password: String, salt: Data, iterations: Int = 10000) -> Data? {
        let keyLength = kCCKeySizeAES256
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

        return status == kCCSuccess ? derivedKey : nil
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
    private func gcmEncryptDecrypt(data: Data, key: Data, iv: Data?, operation: Int) -> Data? {
        guard let iv = iv, iv.count == 12 else {
            print("Invalid IV size for AES-GCM. It must be 12 bytes.")
            return nil
        }

        switch operation {
        case kCCEncrypt:
            return encryptGCM(data: data, withKey: key, iv: iv)
        case kCCDecrypt:
            return decryptGCM(data: data, withKey: key, iv: iv)
        default:
            fatalError("Invalid operation for GCM.")
        }
    }
    
    func encryptGCM(data: Data, withKey key: Data, iv: Data) -> Data? {
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
    
    func decryptGCM(data: Data, withKey key: Data, iv: Data) -> Data? {
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
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: Data())
            return decryptedData
        } catch {
            print("GCM decryption failed: \(error.localizedDescription)")
            return nil
        }
        
    }

}
