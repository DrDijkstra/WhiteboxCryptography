//
//  CryptoKeySize.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-13.
//


import Foundation

public enum CryptoKeySize: Hashable , Equatable{
    // Specific sizes
    case specific(Int)
    
    // Range of key sizes
    case range(Int, Int)
    
    // A helper function to check if a size is valid for this key size type
    func contains(_ size: Int) -> Bool {
        switch self {
        case .specific(let keySize):
            return keySize == size
        case .range(let min, let max):
            return size >= min && size <= max
        }
    }
    
    // Get the key size in bytes for the specified key size in bits
    var keySizeInBytes: Int {
        switch self {
        case .specific(let keySize):
            return keySize / 8  // Convert bits to bytes
        case .range(let min, _):
            return min / 8  // Assuming range minimum is the key size, convert to bytes
        }
    }
    
    public static func == (lhs: CryptoKeySize, rhs: CryptoKeySize) -> Bool {
            switch (lhs, rhs) {
            case (.specific(let lhsSize), .specific(let rhsSize)):
                return lhsSize == rhsSize
            case (.range(let lhsMin, let lhsMax), .range(let rhsMin, let rhsMax)):
                return lhsMin == rhsMin && lhsMax == rhsMax
            default:
                return false
            }
        }
    
    
}
