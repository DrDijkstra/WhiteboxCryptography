//
//  AESCoreError.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import Foundation

enum CryptographicError: Error {
    case invalidKeySize
    case invalidBlockSize
    case encryptionError
    case decryptionError
    case invalidIVSize
    case mandatoryIV
    case cryptOperationFailed(status: Int)
    case authenticationFailed
    case ecbNotAvailableInFasterProcessingType
    case paddingError
    case initializationError
    case fasterGCMisNotAvailableForKeySize192And128
}
