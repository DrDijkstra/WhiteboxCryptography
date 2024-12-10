//
//  AESKeySize.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

public enum AESKeySize: Int {
    case bits128 = 16  // 128 bits = 16 bytes
    case bits192 = 24  // 192 bits = 24 bytes
    case bits256 = 32  // 256 bits = 32 bytes

    // Returns the size of the key in bytes
    var keySizeInBytes: Int {
        return self.rawValue
    }
}
