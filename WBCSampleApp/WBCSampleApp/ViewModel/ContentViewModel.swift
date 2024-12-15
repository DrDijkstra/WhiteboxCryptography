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
    @Published var selectedAlgorithm: CryptoAlgorithm = CryptoAlgorithm.aes(keySize: 256, mode: .ecb, processingType: .regular){
        didSet {
            updateKeySizes() // Update key sizes when algorithm changes
        }
    }
   
    //@Published var aesKeySize: AESKeySize = .bits128
    @Published var aesMode: AESMode = .ecb
    @Published var aesProcessingType: ProcressingType = .regular
    @Published var validKeySizes: [CryptoKeySize] = [] // Added to track valid key sizes
    @Published var selectedKeySize: Int = 256  // Default to 256 bits
    @Published var keySizes: [Int] = [] // Published property to bind to the UI

    private var key:Data = Data()
    private var iv: Data = Data()
    private var memoryKey = "defaultMemoryKey".data(using: .utf8)!
    private let sdk: WhiteboxCryptographySDK
    private var cancellables = Set<AnyCancellable>()
    @Published var algorithms: [CryptoAlgorithm] = [
            .aes(keySize: 128, mode: .ecb, processingType: .regular),
            .des(keySize: 64, processingType: .regular),
            .tripleDES(keySize: 192, processingType: .regular),
            .cast(keySize: 40, processingType: .regular),
            .rc2(keySize: 756, processingType: .regular)
        ]

    private var isEncrypted: Bool = false // Track if encryption was successful

    init() {
        self.sdk = WhiteboxCryptographySDK(memoryKey: memoryKey)
        updateKeySizes()
    }

    private func updateKeySizes() {
        var sizes: [Int] = []
        
        // Loop through each valid key size and handle both specific and range cases
        for keySize in selectedAlgorithm.validKeySizes {
            switch keySize {
            case .specific(let size):
                sizes.append(size)
                
            case .range:
                return
            }
        }
       
        keySizes = sizes
        selectedKeySize = keySizes[0]
       
    }
    
    
    func selectedAlgorithmDescription() -> String {
            switch selectedAlgorithm {
            case .aes:
                return "AES"
            case .des:
                return "DES"
            case .tripleDES:
                return "Triple DES"
            case .cast:
                return "CAST"
            case .rc2:
                return "RC2"
            }
        }
    
    func selectedAlgorithmDescription(for algorithm: CryptoAlgorithm) -> String {
        switch algorithm {
        case .aes:
            return "AES"
        case .des:
            return "DES"
        case .tripleDES:
            return "Triple DES"
        case .cast:
            return "CAST"
        case .rc2:
            return "RC2"
        }
    }


    // Method to encrypt and decrypt text
    func encryptAndDecrypt() {
        // Step 1: Encrypt text
        
        print("selectedAlgorithm \(selectedAlgorithm)")
        if let _ = encryptText() {
            decryptText()
        }

        
    }

    private func encryptText() -> String?{
        do {
            guard !inputText.isEmpty else {
                print("Input text is empty, cannot encrypt.")
                encryptedText = ""
                decryptedText = ""
                isEncrypted = false
                return nil
            }

            let currentAlgorithm = selectedAlgorithm

            // Ensure the IV is created based on the selected algorithm
            guard let ivData = sdk.generateRandomIV(forAlgorithm: currentAlgorithm) else {
                print("Error generating IV")
                encryptedText = ""
                decryptedText = ""
                isEncrypted = false
                return nil
            }

            self.iv = ivData

            // Determine the key size based on the selected AES key size
            self.key = getKeyData(forSize: selectedAlgorithm.keySize)

            if let encryptedData = try sdk.encrypt(
                data: inputText.data(using: .utf8)!,
                withKey: key,
                iv: iv,
                algorithm: currentAlgorithm
            ) {
                encryptedText = encryptedData.base64EncodedString()
                print("Encryption successful: \(encryptedText)")
                isEncrypted = true // Mark as successful
                return encryptedText
            } else {
                encryptedText = ""
                decryptedText = ""
                isEncrypted = false
            }
        } catch {
            print("Encryption error: \(error)")
            encryptedText = ""
            decryptedText = ""
            isEncrypted = false
            return nil
        }
        return nil
    }

    private func decryptText() {
        do {
            guard let encryptedData = Data(base64Encoded: self.encryptedText) else {
                print("Invalid base64 encoded string.")
                decryptedText = "Decryption failed"
                return
            }

            let currentAlgorithm = selectedAlgorithm

            // Decrypt with the same key and IV used for encryption

            if let decryptedData = try sdk.decrypt(
                data: encryptedData,
                withKey: key,
                iv: iv,
                algorithm: currentAlgorithm
            ) {
                decryptedText = String(data: decryptedData, encoding: .utf8) ?? "Decryption failed"
                print("Decryption successful: \(decryptedText)")
            } else {
                decryptedText = "Decryption failed"
            }
        } catch {
            print("Decryption error: \(error)")
            decryptedText = "Decryption failed"
        }
    }

    // Helper function to determine key data for the selected AES key size
    private func getKeyData(forSize sizeInBits: Int) -> Data {
        let sizeInBytes = sizeInBits / 8 // Convert bits to bytes
        var keyData = Data(count: sizeInBytes)
        
        // Generate random bytes and fill the Data object
        let result = keyData.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, sizeInBytes, bytes.baseAddress!)
        }
        
        // Check for errors and return the keyData
        if result == errSecSuccess {
            return keyData
        } else {
            // Handle the error (you can return an empty Data or handle it differently)
            fatalError("Failed to generate random key data")
        }
    }
    
    func updateAlgorithmWithKeySize(updatedkeysize: Int) {
        self.selectedKeySize = updatedkeysize
        switch selectedAlgorithm {
        case .aes(_, let mode, let processingType):
            selectedAlgorithm = .aes(keySize: updatedkeysize, mode: mode, processingType: processingType)
        case .des(_, let processingType):
            selectedAlgorithm = .des(keySize: updatedkeysize, processingType: processingType)
        case .tripleDES(_, let processingType):
            selectedAlgorithm = .tripleDES(keySize: updatedkeysize, processingType: processingType)
        case .cast(_, let processingType):
            selectedAlgorithm  = .cast(keySize: updatedkeysize, processingType: processingType)
        case .rc2(_, let processingType):
            selectedAlgorithm = .rc2(keySize: updatedkeysize, processingType: processingType)
        }
    }
    
    func updateProccessingType(processingType: ProcressingType) {
        self.aesProcessingType = processingType
        switch selectedAlgorithm {
        case .aes:
            selectedAlgorithm = .aes(keySize: selectedAlgorithm.keySize, mode: selectedAlgorithm.aesMode!, processingType: processingType)
        case .des:
            selectedAlgorithm = .des(keySize: selectedAlgorithm.keySize, processingType: processingType)
        case .tripleDES:
            selectedAlgorithm = .tripleDES(keySize: selectedAlgorithm.keySize, processingType: processingType)
        case .cast:
            selectedAlgorithm = .cast(keySize: selectedAlgorithm.keySize, processingType: processingType)
        case .rc2:
            selectedAlgorithm = .rc2(keySize: selectedAlgorithm.keySize, processingType: processingType)

        }
        
    }

}
