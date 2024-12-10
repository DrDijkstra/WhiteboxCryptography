//
//  CryptographyProtocol.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation

public protocol CryptographicService {
    func encrypt(data: Data, withKey key: Data) -> Data?
    func decrypt(data: Data, withKey key: Data) -> Data?
}

