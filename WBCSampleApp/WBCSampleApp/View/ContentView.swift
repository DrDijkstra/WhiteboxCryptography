//
//  ContentView.swift
//  WBCSampleApp
//
//  Created by Sanjay Dey on 2024-12-10.
//

import SwiftUI
import Combine
import WhiteboxCryptography

struct ContentView: View {
    @StateObject private var viewModel = ContentViewModel()
    @FocusState private var isTextFieldFocused: Bool
    @State private var showErrorAlert = false
    @State private var errorMessage = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Input Text Field
                TextField("Enter text to encrypt", text: $viewModel.inputText)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                    .focused($isTextFieldFocused)

                // Algorithm Picker
                AlgorithmPickerView(viewModel: viewModel)

                // Key Size Picker
                KeySizePickerView(viewModel: viewModel)

                // AES Mode Picker (only for AES)
                if case .aes = viewModel.selectedAlgorithm {
                    AesModePickerView(viewModel: viewModel)
                }

                // Processing Type Picker
                ProcessingTypePickerView(viewModel: viewModel)

                // Encrypt & Decrypt Button
                Button("Encrypt & Decrypt") {
                    encryptAndDecrypt()
                }
                .frame(maxWidth: .infinity)
                .buttonStyle(.borderedProminent)
                .padding()

                // Display Results
                EncryptedDecryptedTextView(viewModel: viewModel)

                Spacer()
            }
            .padding()
            .onTapGesture {
                isTextFieldFocused = false
            }
            .alert(isPresented: $showErrorAlert) {
                Alert(title: Text("Error"), message: Text(errorMessage), dismissButton: .default(Text("OK")))
            }
        }
    }
    
    // Handle encryption and decryption actions
    private func encryptAndDecrypt() {
        viewModel.encryptAndDecrypt()
    }
}

// Algorithm Picker View
struct AlgorithmPickerView: View {
    @ObservedObject var viewModel: ContentViewModel

    var body: some View {
        VStack(alignment: .leading) {
            Text("Select an encryption algorithm:")
                .font(.headline)

            Picker("Algorithm", selection: $viewModel.selectedAlgorithm) {
                ForEach(viewModel.algorithms, id: \.self) { algorithm in
                    Text(viewModel.selectedAlgorithmDescription(for: algorithm))
                        .tag(algorithm)
                }
            }
            .pickerStyle(MenuPickerStyle())
            .onChange(of: viewModel.selectedAlgorithm) { _,_ in
                viewModel.updateKeySizes()
            }
        }
        .padding(.bottom, 8)
    }
}

// Key Size Picker View
struct KeySizePickerView: View {
    @ObservedObject var viewModel: ContentViewModel

    var body: some View {
        VStack(alignment: .leading) {
            Text("Select key size:")
                .font(.headline)

            let validKeySizes = viewModel.selectedAlgorithm.validKeySizes
            if let firstKeySize = validKeySizes.first {
                switch firstKeySize {
                case .specific:
                    Picker("Select Key Size", selection: $viewModel.selectedKeySize) {
                        ForEach(viewModel.keySizes, id: \.self) { size in
                            Text("\(size) bits")
                                .tag(size)
                        }
                    }
                    .pickerStyle(MenuPickerStyle())
                    
                case .range(let min, let max):
                    VStack {
                        Text("Key Size: \(viewModel.selectedKeySize) bits")
                        Slider(value: Binding(get: {
                            Double(viewModel.selectedKeySize)
                        }, set: { newValue in
                            viewModel.selectedKeySize = Int(newValue)
                        }), in: Double(min)...Double(max), step: 1)
                        .onChange(of: viewModel.selectedKeySize) { _,newKeySize in
                            viewModel.updateAlgorithmWithKeySize(updatedKeySize: newKeySize)
                        }
                        Text("Range: \(min) bits to \(max) bits")
                            .font(.subheadline)
                            .foregroundColor(.gray)
                    }
                }
            }
        }
        .padding(.bottom, 8)
    }
}

// AES Mode Picker View
struct AesModePickerView: View {
    @ObservedObject var viewModel: ContentViewModel

    var body: some View {
        VStack(alignment: .leading) {
            Text("Select AES mode:")
                .font(.headline)

            Picker("Mode", selection: $viewModel.aesMode) {
                Text("ECB").tag(AESMode.ecb)
                Text("CBC").tag(AESMode.cbc)
                Text("GCM").tag(AESMode.gcm)
            }
            .pickerStyle(MenuPickerStyle())
            .onChange(of: viewModel.aesMode) { _,newMode in
                viewModel.selectedAlgorithm = .aes(
                    keySize: viewModel.selectedKeySize,
                    mode: newMode,
                    processingType: viewModel.selectedAlgorithm.processingType
                )
            }
        }
        .padding(.bottom, 8)
    }
}

// Processing Type Picker View
struct ProcessingTypePickerView: View {
    @ObservedObject var viewModel: ContentViewModel

    var body: some View {
        VStack(alignment: .leading) {
            Text("Select processing type:")
                .font(.headline)

            Picker("Processing Type", selection: $viewModel.aesProcessingType) {
                Text("Faster").tag(ProcressingType.faster)
                Text("Regular").tag(ProcressingType.regular)
            }
            .pickerStyle(MenuPickerStyle())
            .onChange(of: viewModel.aesProcessingType) { _,newProcessingType in
                viewModel.updateProcessingType(processingType: newProcessingType)
            }
        }
        .padding(.bottom, 8)
    }
}

// Encrypted and Decrypted Text View
struct EncryptedDecryptedTextView: View {
    @ObservedObject var viewModel: ContentViewModel

    var body: some View {
        VStack(alignment: .leading) {
            if !viewModel.encryptedText.isEmpty {
                Text("Encrypted Text: \(viewModel.encryptedText)")
                    .padding()
            }

            if !viewModel.decryptedText.isEmpty {
                Text("Decrypted Text: \(viewModel.decryptedText)")
                    .padding()
            }
        }
    }
}

// Preview
#Preview {
    ContentView()
}
