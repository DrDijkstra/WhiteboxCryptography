//
//  CryptoAlgorithm.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public enum CryptoAlgorithm: Hashable, Equatable {
    case aes(keySize: Int, mode: AESMode, processingType: ProcressingType)
    case des(keySize: Int, processingType: ProcressingType)
    case tripleDES(keySize: Int, processingType: ProcressingType)
    case cast(keySize: Int, processingType: ProcressingType)
    case rc2(keySize: Int, processingType: ProcressingType)

    
    // The key size in bits for the algorithm
    public var keySize: Int {
        switch self {
        case .aes(let size, _, _):
            return size
        case .des(let size, _):
            return size
        case .tripleDES(let size, _):
            return size
        case .cast(let size, _):
            return size
        case .rc2(let size, _):
            return size
        }
    }
    
    public var processingType: ProcressingType {
        switch self {
        case .aes(_, _, let processingType):
            return processingType
        case .des(_, let processingType):
            return processingType
        case .tripleDES(_, let processingType):
            return processingType
        case .cast(_, let processingType):
            return processingType
        case .rc2(_, let processingType):
            return processingType
        }
    }

    // Size of the initialization vector (IV) required for the algorithm
    var ivSize: Int {
        switch self {
        case .aes(_, let mode, _):
            switch mode {
            case .cbc:
                return kCCBlockSizeAES128 // 16 bytes for AES CBC
            case .gcm:
                return 12 // 12 bytes for AES GCM
            default:
                return 16
            }
        case .des:
            return kCCBlockSizeDES // 8 bytes for DES
        case .tripleDES:
            return kCCBlockSize3DES // 8 bytes for Triple DES
        case .cast:
            return kCCBlockSizeCAST // 8 bytes for CAST
        case .rc2:
            return kCCBlockSizeRC2 // 8 bytes for RC2
        }
    }

    // Validate if a key size is valid for the algorithm (in bits)
    func validateKeySize(_ keySize: Int) throws {
        switch self {
        case .aes:
            guard keySize == 128 || keySize == 192 || keySize == 256 else {
                throw CryptographicError.invalidKeySize("AES requires a key size of 128, 192, or 256 bits. Provided: \(keySize)")
            }
        case .des:
            guard keySize == 64 else {
                throw CryptographicError.invalidKeySize("DES requires a key size of 56 bits. Provided: \(keySize)")
            }
        case .tripleDES:
            guard keySize == 192 else {
                throw CryptographicError.invalidKeySize("Triple DES requires a key size of 112 or 168 bits. Provided: \(keySize)")
            }
        case .cast:
            guard keySize == 40 else {
                throw CryptographicError.invalidKeySize("CAST requires a key size of 40 bits. Provided: \(keySize)")
            }
        case .rc2:
            guard keySize >= 8 && keySize <= 1024 else {
                throw CryptographicError.invalidKeySize("RC2 requires a key size between 8 and 1024 bits. Provided: \(keySize)")
            }
        }
    }


    // Convert CryptoAlgorithm to CommonCrypto CCAlgorithm
    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .aes(_, let mode, _):
            switch mode {
            case .cbc, .ecb:
                return CCAlgorithm(kCCAlgorithmAES)
            case .gcm:
                return CCAlgorithm(kCCAlgorithmAES) // AES-GCM uses the same AES algorithm
            }
        case .des:
            return CCAlgorithm(kCCAlgorithmDES)
        case .tripleDES:
            return CCAlgorithm(kCCAlgorithm3DES)
        case .cast:
            return CCAlgorithm(kCCAlgorithmCAST)
        case .rc2:
            return CCAlgorithm(kCCAlgorithmRC2)
        }
    }
    
    public var validKeySizes: [CryptoKeySize] {
        switch self {
        case .aes(_,let mode,let processingType):
            switch processingType {
            case .faster:
                switch mode {
                case .gcm:
                    return [.specific(256)]
                default:
                    return [.specific(128), .specific(192), .specific(256)]
                }
            default:
                return [.specific(128), .specific(192), .specific(256)]
            }
             // AES valid key sizes in bits
        case .des:
            return [.specific(64)] // DES valid key size in bits
        case .tripleDES:
            return [.specific(192)] // Triple DES valid key sizes in bits
        case .cast:
            return [.specific(40)] // CAST valid key size in bits
        case .rc2:
            return [.range(8, 1024)] // RC2 valid key sizes in bits (from 8 to 1024)
        }
    }

    // Convert CryptoAlgorithm to the corresponding CCOptions
    var ccOptions: CCOptions {
        switch self {
        case .aes(_, let mode, _):
            switch mode {
            case .cbc, .ecb:
                return CCOptions(kCCOptionPKCS7Padding)
            case .gcm:
                return CCOptions(0) // AES-GCM does not require padding
            }
        case .des, .tripleDES, .cast, .rc2:
            return CCOptions(kCCOptionPKCS7Padding)
        }
    }

    // Equatable Conformance: Compare two CryptoAlgorithm instances
    public static func == (lhs: CryptoAlgorithm, rhs: CryptoAlgorithm) -> Bool {
        switch (lhs, rhs) {
        case (.aes(let lhsKeySize, let lhsMode, let lhsProcessingType), .aes(let rhsKeySize, let rhsMode, let rhsProcessingType)):
            return lhsKeySize == rhsKeySize && lhsMode == rhsMode && lhsProcessingType == rhsProcessingType
        case (.des(let lhsKeySize, let lhsProcessingType), .des(let rhsKeySize, let rhsProcessingType)):
            return lhsKeySize == rhsKeySize && lhsProcessingType == rhsProcessingType
        case (.tripleDES(let lhsKeySize, let lhsProcessingType), .tripleDES(let rhsKeySize, let rhsProcessingType)):
            return lhsKeySize == rhsKeySize && lhsProcessingType == rhsProcessingType
        case (.cast(let lhsKeySize, let lhsProcessingType), .cast(let rhsKeySize, let rhsProcessingType)):
            return lhsKeySize == rhsKeySize && lhsProcessingType == rhsProcessingType
        case (.rc2(let lhsKeySize, let lhsProcessingType), .rc2(let rhsKeySize, let rhsProcessingType)):
            return lhsKeySize == rhsKeySize && lhsProcessingType == rhsProcessingType
        default:
            return false
        }
    }
    
    func validateIVSize( iv: Data?) throws {
        guard let iv = iv else {
            throw CryptographicError.mandatoryIV
        }

        if iv.count != self.ivSize {
            throw CryptographicError.invalidIVSize(expected: self.ivSize, actual: iv.count)
        }
    }
}
