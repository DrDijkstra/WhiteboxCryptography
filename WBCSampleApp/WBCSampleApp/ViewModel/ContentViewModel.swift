//
//  ContentViewModel.swift
//  WBCSampleApp
//
//  Created by Sanjay Dey on 2024-12-10.
//


import Foundation
import Combine
import WhiteboxCryptography

class ContentViewModel: ObservableObject {
    @Published var inputText: String = ""
    @Published var encryptedText: String = ""
    @Published var decryptedText: String = ""
    @Published var selectedAlgorithm: CryptoAlgorithm = .aes(keySize: 256, mode: .ecb, processingType: .regular) {
        didSet {
            updateKeySizes()
        }
    }
    
    @Published var aesMode: AESMode = .ecb
    @Published var aesProcessingType: ProcressingType = .regular
    @Published var validKeySizes: [CryptoKeySize] = [] // Track valid key sizes
    @Published var selectedKeySize: Int = 256  // Default to 256 bits
    @Published var keySizes: [Int] = [] // Key size options

    private var key: Data = Data()
    private var iv: Data = Data()
    private let sdk: WhiteboxCryptographySDK
    private var cancellables = Set<AnyCancellable>()

    @Published var algorithms: [CryptoAlgorithm] = [
        .aes(keySize: 128, mode: .ecb, processingType: .regular),
        .des(keySize: 64, processingType: .regular),
        .tripleDES(keySize: 192, processingType: .regular),
        .cast(keySize: 40, processingType: .regular),
        .rc2(keySize: 756, processingType: .regular)
    ]

    private var isEncrypted: Bool = false

    init(sdk: WhiteboxCryptographySDK = WhiteboxCryptographySDK(memoryKey: "defaultMemoryKey".data(using: .utf8)!)) {
        self.sdk = sdk
        updateKeySizes()
    }

    // MARK: - Algorithm Management
    func updateKeySizes() {
        var sizes: [Int] = []
        
        // Add key sizes based on selected algorithm
        for keySize in selectedAlgorithm.validKeySizes {
            switch keySize {
            case .specific(let size):
                sizes.append(size)
            case .range:
                return
            }
        }
        
        keySizes = sizes
        selectedKeySize = keySizes.first ?? 256
    }

    func selectedAlgorithmDescription() -> String {
        return selectedAlgorithm.description
    }

    func selectedAlgorithmDescription(for algorithm: CryptoAlgorithm) -> String {
        return algorithm.description
    }

    // MARK: - Encryption and Decryption
    func encryptAndDecrypt() {
        guard let encrypted = encryptText() else {
            print("Encryption failed.")
            return
        }
        decryptText(with: encrypted)
    }

    private func encryptText() -> String? {
        guard !inputText.isEmpty else {
            print("Input text is empty, cannot encrypt.")
            resetEncryptedAndDecryptedText()
            return nil
        }

        do {
            let currentAlgorithm = selectedAlgorithm

            // Generate IV based on the selected algorithm
            guard let ivData = sdk.generateRandomIV(forAlgorithm: currentAlgorithm) else {
                print("Error generating IV.")
                resetEncryptedAndDecryptedText()
                return nil
            }

            self.iv = ivData
            self.key = getKeyData(forSize: selectedKeySize)

            // Perform encryption
            guard let encryptedData = try sdk.encrypt(
                data: inputText.data(using: .utf8)!,
                withKey: key,
                iv: iv,
                algorithm: currentAlgorithm
            ) else {
                print("Encryption failed.")
                resetEncryptedAndDecryptedText()
                return nil
            }

            encryptedText = encryptedData.base64EncodedString()
            isEncrypted = true
            print("Encryption successful: \(encryptedText)")
            return encryptedText
        } catch {
            print("Encryption error: \(error)")
            resetEncryptedAndDecryptedText()
            return nil
        }
    }

    private func decryptText(with encryptedText: String) {
        guard let encryptedData = Data(base64Encoded: encryptedText) else {
            print("Invalid base64 encoded string.")
            decryptedText = "Decryption failed."
            return
        }

        do {
            let currentAlgorithm = selectedAlgorithm

            // Perform decryption
            guard let decryptedData = try sdk.decrypt(
                data: encryptedData,
                withKey: key,
                iv: iv,
                algorithm: currentAlgorithm
            ) else {
                decryptedText = "Decryption failed."
                return
            }

            decryptedText = String(data: decryptedData, encoding: .utf8) ?? "Decryption failed."
            print("Decryption successful: \(decryptedText)")
        } catch {
            print("Decryption error: \(error)")
            decryptedText = "Decryption failed."
        }
    }

    // MARK: - Key Management
    private func getKeyData(forSize sizeInBits: Int) -> Data {
        let sizeInBytes = sizeInBits / 8
        var keyData = Data(count: sizeInBytes)

        let result = keyData.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, sizeInBytes, bytes.baseAddress!)
        }

        guard result == errSecSuccess else {
            fatalError("Failed to generate random key data.")
        }

        return keyData
    }

    func updateAlgorithmWithKeySize(updatedKeySize: Int) {
        self.selectedKeySize = updatedKeySize
        switch selectedAlgorithm {
        case .aes(_, let mode, let processingType):
            selectedAlgorithm = .aes(keySize: updatedKeySize, mode: mode, processingType: processingType)
        case .des(_, let processingType):
            selectedAlgorithm = .des(keySize: updatedKeySize, processingType: processingType)
        case .tripleDES(_, let processingType):
            selectedAlgorithm = .tripleDES(keySize: updatedKeySize, processingType: processingType)
        case .cast(_, let processingType):
            selectedAlgorithm = .cast(keySize: updatedKeySize, processingType: processingType)
        case .rc2(_, let processingType):
            selectedAlgorithm = .rc2(keySize: updatedKeySize, processingType: processingType)
        }
    }

    func updateProcessingType(processingType: ProcressingType) {
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

    // MARK: - Helper Methods
    private func resetEncryptedAndDecryptedText() {
        encryptedText = ""
        decryptedText = ""
        isEncrypted = false
    }
}

extension CryptoAlgorithm {
    var description: String {
        switch self {
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
}
