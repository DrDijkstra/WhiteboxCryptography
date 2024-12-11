//
//  ContentViewModel.swift
//  WBCSampleApp
//
//  Created by Sanjay Dey on 2024-12-10.
//


import SwiftUI
import Combine
import WhiteboxCryptography

class ContentViewModel: ObservableObject {
    @Published var inputText: String = ""
    @Published var encryptedText: String = ""
    @Published var decryptedText: String = ""
    
    private var iv: Data = Data()
    private var algo: CryptoAlgorithm = .aes(keySize: .bits256, mode: .cbc)
    
    // Initialize with a fixed memory key (converted to Data)
    let memoryKey = "defaultMemoryKey".data(using: .utf8)!
    
    // SDK initialization with memoryKey
    private var sdk: WhiteboxCryptographySDK
    private var cancellables = Set<AnyCancellable>()
    
    // Initialize SDK in the constructor
    init() {
        self.sdk = WhiteboxCryptographySDK(memoryKey: self.memoryKey)
        
        // Observe encrypted text and decrypt it when changed
        $encryptedText
            .receive(on: DispatchQueue.main)  // Make sure this runs on the main thread to update UI
            .sink { [weak self] encrypted in
                if !encrypted.isEmpty {
                    self?.decryptText()
                }
            }
            .store(in: &cancellables)
    }
    
    func encryptText() {
        guard !inputText.isEmpty else { return }
        
        // Generate an Initialization Vector (IV) for encryption
        guard let ivData = self.sdk.generateRandomIV(forAlgorithm: algo)  else{
            return print("Error generating IV")
        }
        self.iv = ivData
        // Use a 16-byte IV (AES block size)
        let key = self.memoryKey // Use the memoryKey for the encryption key
        
        // You may want to use an algorithm like AES in CBC mode
        let algorithm: CryptoAlgorithm = .aes(keySize: .bits256, mode: .cbc) // Assuming your SDK supports it
        
        // Encrypt the input text
        if let encryptedData = sdk.encrypt(data: inputText.data(using: .utf8)!,
                                           withKey: key,
                                           iv: iv,
                                           algorithm: algorithm) {
            encryptedText = encryptedData.base64EncodedString()
            print("encryptedText \(encryptedText)")
        }
    }
    
    func decryptText() {
        guard !encryptedText.isEmpty else {
            return
        }
        
        // Convert the base64 encoded string back to data
        if let encryptedData = Data(base64Encoded: encryptedText) {
            _ = Data(count: 16) // Same 16-byte IV used for encryption
            let key = self.memoryKey // Use the same key as for encryption
            
            // Decrypt the text
            if let decryptedData = sdk.decrypt(data: encryptedData,
                                                withKey: key,
                                                iv: self.iv,
                                                algorithm: algo) {
                decryptedText = String(data: decryptedData, encoding: .utf8) ?? "Decryption failed"
            } else {
                decryptedText = "Decryption failed"
            }
        }
    }
}
