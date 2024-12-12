//
//  AESCoreError.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-12.
//


import Foundation

enum AESCoreError: Error {
    case invalidKeySize
    case invalidBlockSize
    case encryptionError
    case invalidIVSize
    case authenticationFailed
    case paddingError
}