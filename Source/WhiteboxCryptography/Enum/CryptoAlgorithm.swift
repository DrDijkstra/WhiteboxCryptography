//
//  CryptoAlgorithm.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public enum CryptoAlgorithm {
    case aes(keySize: AESKeySize, mode: AESMode, processingType: AESProcressingType)
    case des
    case tripleDES
    case cast
    case rc2

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
}
