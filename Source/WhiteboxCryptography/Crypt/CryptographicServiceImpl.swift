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
class CryptographicServiceImpl: CryptographicService {
    
    private var aesService: AESService
    
    init(aesService: AESService = AESServiceImpl()) {
        self.aesService = aesService
    }

    // MARK: - Cryptographic operation (encryption or decryption)
    private func crypt(data: Data, key: Data, iv: Data?, operation: Int, algorithm: CryptoAlgorithm) throws -> Data? {
            switch algorithm {
            case .aes(_, let mode):
                return try aesServiceCrypt(data: data, key: key, iv: iv, operation: operation, mode: mode)
            default:
                guard let iv = iv else {
                    throw CryptographicError.mandatoryIV
                }
                
                // Proceed with cryptographic operation (encryption or decryption)
                var result = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
                var resultLength = 0

                let ivPointer = iv.withUnsafeBytes { $0.baseAddress } ?? nil

                let status = key.withUnsafeBytes { keyPointer in
                    data.withUnsafeBytes { dataPointer in
                        CCCrypt(
                            CCOperation(operation),
                            algorithm.ccAlgorithm,
                            algorithm.ccOptions,
                            keyPointer.baseAddress, key.count,
                            ivPointer,
                            dataPointer.baseAddress, data.count,
                            &result, result.count,
                            &resultLength
                        )
                    }
                }

                guard status == kCCSuccess else {
                    throw CryptographicError.cryptOperationFailed(status: Int(status))
                }

                return Data(result.prefix(resultLength))
            }
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
    func encrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CryptoAlgorithm) throws -> Data? {
        return try crypt(data: data, key: key, iv: iv, operation: kCCEncrypt, algorithm: algorithm)
    }

    // MARK: - AES Decryption with IV (CBC or GCM)
    func decrypt(data: Data, withKey key: Data, iv: Data? = nil, algorithm: CryptoAlgorithm) throws -> Data? {
        return try crypt(data: data, key: key, iv: iv, operation: kCCDecrypt, algorithm: algorithm)
    }

    // MARK: - Generate Random Key for Specified Algorithm
    func generateRandomKey(forAlgorithm algorithm: CryptoAlgorithm) -> Data? {
        let keyLength: Int

        switch algorithm {
        case .aes(let keySize, _):
            keyLength = aesKeyLength(for: keySize)
        case .des:
            keyLength = 8
        case .tripleDES:
            keyLength = 24
        case .rc2:
            keyLength = 16
        case .cast:
            keyLength = 16
        }

        return generateRandomData(ofLength: keyLength)
    }

    // MARK: - Generate Random IV
    func generateRandomIV(forAlgorithm algorithm: CryptoAlgorithm) -> Data? {
        return generateRandomData(ofLength: algorithm.ivSize)
    }

    private func generateRandomData(ofLength length: Int) -> Data? {
        var data = Data(count: length)
        let result = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, length, bytes.baseAddress!)
        }
        return result == errSecSuccess ? data : nil
    }

    // MARK: - AES Key Length Calculation
    private func aesKeyLength(for size: AESKeySize) -> Int {
        switch size {
        case .bits128:
            return kCCKeySizeAES128
        case .bits192:
            return kCCKeySizeAES192
        case .bits256:
            return kCCKeySizeAES256
        }
    }

    // MARK: - Key Derivation using PBKDF2
    func deriveKey(fromPassword password: String, salt: Data, iterations: Int = 10000) -> Data? {
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
    func hmac(data: Data, key: Data) -> Data? {
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
}
