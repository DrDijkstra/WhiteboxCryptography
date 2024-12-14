//
//  AESCoreError.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import Foundation

enum CryptographicError: Error {
    case invalidBlockSize
    case encryptionError
    case decryptionError
    case mandatoryIV
    case cryptOperationFailed(status: Int)
    case authenticationFailed
    case ecbNotAvailableInFasterProcessingType
    case paddingError
    case initializationError
    case fasterGCMisNotAvailableForKeySize192And128
    case invalidKeySizeForTripleDES
    case invalidIVSizeForTripleDES
    case invalidIVSize(expected: Int, actual: Int)
    case invalidKeySize(String)
}
