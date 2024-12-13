//
//  Array+Extesion.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//

import Foundation

extension Array where Element == UInt8 {
    var hexString: String {
        return self.map { String(format: "%02x ", $0) }.joined()
    }
    
    func asciiValuesString() -> String {
        return self.map { String($0) }.joined(separator: " ")
    }
    
    // Converts each byte to its character representation (if printable)
    func asciiCharactersString() -> String {
        return self.map { byte in
            // Check if the byte is a printable ASCII character (0x20 to 0x7E)
            if (0x20...0x7E).contains(byte) {
                return String(UnicodeScalar(byte))
            } else {
                return "?" // Use '?' for non-printable characters.
            }
        }.joined()
    }
}
