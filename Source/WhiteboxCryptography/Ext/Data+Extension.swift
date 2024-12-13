//
//  Data+Extension.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//

import Foundation

extension Data {
    // Convert Data to a hexadecimal string
    func toHexString() -> String {
        return self.map { String(format: "%02hhx", $0) }.joined()
    }

    // Convert Data to a Base64 encoded string
    func toBase64String() -> String {
        return self.base64EncodedString()
    }
}
