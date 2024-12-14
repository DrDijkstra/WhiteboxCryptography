//
//  CryptoAlgorithm.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public enum CryptoAlgorithm: Hashable, Equatable {
    case aes(keySize: Int, mode: AESMode, processingType: AESProcressingType)
    case des(keySize: Int)
    case tripleDES(keySize: Int)
    case cast(keySize: Int)
    case rc2(keySize: Int)

    // Initialize CryptoAlgorithm with validation
    public init?(keySize: Int, mode: AESMode? = nil, processingType: AESProcressingType? = nil) throws {
        switch keySize {
        case 56: // DES case, fixed key size in bits
            self = .des(keySize: keySize)
        case 112, 168: // Triple DES case, fixed key size in bits
            self = .tripleDES(keySize: keySize)
        case 40: // CAST case, fixed key size in bits
            self = .cast(keySize: keySize)
        case let size where size >= 8 && size <= 1024: // RC2 case, key size in bits
            self = .rc2(keySize: size)
        case 128, 192, 256: // AES cases (128, 192, 256 bits)
            if let mode = mode, let processingType = processingType {
                self = .aes(keySize: keySize, mode: mode, processingType: processingType)
            } else {
                throw CryptographicError.invalidKeySize
            }
        default:
            throw CryptographicError.invalidKeySize
        }
    }
    
    // The key size in bits for the algorithm
    public var keySize: Int {
        switch self {
        case .aes(let size, _, _):
            return size
        case .des(let size):
            return size
        case .tripleDES(let size):
            return size
        case .cast(let size):
            return size
        case .rc2(let size):
            return size
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
    func isValidKeySize(_ keySize: Int) -> Bool {
        switch self {
        case .aes:
            return keySize == 128 || keySize == 192 || keySize == 256 // AES valid key sizes in bits
        case .des:
            return keySize == 56 // DES valid key size in bits
        case .tripleDES:
            return keySize == 112 || keySize == 168 // Triple DES valid key sizes in bits
        case .cast:
            return keySize == 40 // CAST valid key size in bits
        case .rc2:
            return keySize >= 8 && keySize <= 1024 // RC2 valid key sizes in bits
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
    
    var validKeySizes: [CryptoKeySize] {
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
            return [.specific(56)] // DES valid key size in bits
        case .tripleDES:
            return [.specific(112), .specific(168)] // Triple DES valid key sizes in bits
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
        case (.des(let lhsKeySize), .des(let rhsKeySize)):
            return lhsKeySize == rhsKeySize
        case (.tripleDES(let lhsKeySize), .tripleDES(let rhsKeySize)):
            return lhsKeySize == rhsKeySize
        case (.cast(let lhsKeySize), .cast(let rhsKeySize)):
            return lhsKeySize == rhsKeySize
        case (.rc2(let lhsKeySize), .rc2(let rhsKeySize)):
            return lhsKeySize == rhsKeySize
        default:
            return false
        }
    }
}
