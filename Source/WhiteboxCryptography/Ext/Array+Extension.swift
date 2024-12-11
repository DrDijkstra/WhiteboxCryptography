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
}
