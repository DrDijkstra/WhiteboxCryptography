//
//  MemoryScramblerProtocol.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//

import Foundation

protocol MemoryScrambler {
    func scramble(data: Data, withKey key: Data) -> Data
    func descramble(data: Data, withKey key: Data) -> Data
}
