//
//  AESService.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-11.
//

import Foundation

class AESServiceImpl: AESService {
    func encrypt(block: Data, iv: Data) -> Data? {
        return Data()
    }
    
    func decrypt(block: Data, iv: Data) -> Data? {
        return Data()
    }
    
    private var aes: AESCore
    
    init(aes: AESCore) throws {
        self.aes = aes
    }
}
