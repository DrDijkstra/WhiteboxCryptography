//
//  AESMode.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//


public enum AESMode: Hashable {
    case ecb, cbc, gcm
}

public enum AESProcressingType:Hashable {
    case faster
    case regular
}
