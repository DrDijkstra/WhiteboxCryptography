//
//  AES.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//


import Foundation

// Protocol for AES encryption and decryption functionality
protocol AESService {    
    func encrypt(block: Data) -> Data?
    func decrypt(block: Data) -> Data?
}

