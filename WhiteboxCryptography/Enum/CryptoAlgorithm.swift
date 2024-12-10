//
//  CryptoAlgorithm.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation
import CommonCrypto

public enum CryptoAlgorithm {
    case aes(keySize: AESKeySize, mode: AESMode)
    case des
    case tripleDES
    case cast
    case rc2

    var ivSize: Int {
        switch self {
        case .aes(_, let mode):
            switch mode {
            case .cbc:
                return kCCBlockSizeAES128 // 16 bytes
            case .gcm:
                return 12 // 12 bytes for AES-GCM
            }
        case .des:
            return kCCBlockSizeDES // 8 bytes
        case .tripleDES:
            return kCCBlockSize3DES // 8 bytes
        case .cast:
            return kCCBlockSizeCAST // 8 bytes
        case .rc2:
            return kCCBlockSizeRC2 // 8 bytes
        }
    }
}

public enum AESKeySize: Int {
    case bits128 = 16  // 128 bits = 16 bytes
    case bits192 = 24  // 192 bits = 24 bytes
    case bits256 = 32  // 256 bits = 32 bytes
}

public enum AESMode {
    case cbc // Cipher Block Chaining
    case gcm // Galois/Counter Mode
}
