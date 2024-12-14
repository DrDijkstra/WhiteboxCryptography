//
//  AESMode.swift
//  WhiteboxCryptography
//
//  Created by Sanjay Dey on 2024-12-10.
//


public enum AESMode: String, Hashable {
    case ecb, cbc, gcm
}

public enum ProcressingType:String, Hashable {
    case faster
    case regular
}
