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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Text field for input text
                TextField("Enter text to encrypt", text: $viewModel.inputText)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .padding()
                    .focused($isTextFieldFocused) // Bind the focus state

                // Picker for selecting encryption algorithm
                HStack(alignment: .center) {
                    Text("Select an encryption algorithm:")
                        .font(.headline) // Descriptive text for the picker
                        .padding(.bottom, 4) // Adds space between text and picker

                    Picker("Algorithm", selection: $viewModel.selectedAlgorithm) {
                        ForEach(viewModel.algorithms, id: \.self) { algorithm in
                            Text(viewModel.selectedAlgorithmDescription(for: algorithm))
                                .tag(algorithm)
                        }
                    }
                    .pickerStyle(MenuPickerStyle())
                    .onChange(of: viewModel.selectedAlgorithm) { oldAlgorithm, newAlgorithm in
                        // When algorithm changes, update the valid key sizes
                        viewModel.selectedAlgorithm = newAlgorithm
                    }
                }

                // Key Size Picker for selected algorithm
                HStack(alignment: .center) {
                    Text("Select key size:")
                        .font(.headline) // Descriptive text for the key size picker
                        .padding(.bottom, 4) // Adds space between text and picker

                    let validKeySizes = viewModel.selectedAlgorithm.validKeySizes
                    switch validKeySizes.first {
                    case .specific:
                        // For specific key sizes, use a HStack for the Picker
                        Picker("Select Key Size", selection: $viewModel.selectedKeySize) {
                            ForEach(viewModel.keySizes, id: \.self) { size in
                                Text("\(size) bits")
                                    .tag(size)
                            }
                        }
                        .pickerStyle(MenuPickerStyle())
                        
                    case .range(let min, let max):
                        // For range key sizes, conditionally use VStack inside the HStack
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Key Size: \(viewModel.selectedKeySize) bits")
                                .padding(.bottom, 4)

                            Slider(value: Binding(get: {
                                Double(viewModel.selectedKeySize)
                            }, set: { newValue in
                                viewModel.selectedKeySize = Int(newValue)
                            }), in: Double(min)...Double(max), step: 1)
                                .onChange(of: viewModel.selectedKeySize) { _, newKeySize in
                                    viewModel.updateAlgorithmWithKeySize(updatedkeysize: newKeySize)
                                }

                            Text("Range: \(min) bits to \(max) bits")
                                .font(.subheadline)
                                .foregroundColor(.gray)
                        }

                    default:
                        EmptyView()
                    }
                }


                // AES Mode Picker if AES is selected
                if case .aes = viewModel.selectedAlgorithm {
                    HStack(alignment: .center) {
                        Text("Select AES mode:")
                            .font(.headline) // Descriptive text for AES mode picker
                            .padding(.bottom, 4) // Adds space between text and picker

                        Picker("Mode", selection: $viewModel.aesMode) {
                            Text("ECB").tag(AESMode.ecb)
                            Text("CBC").tag(AESMode.cbc)
                            Text("GCM").tag(AESMode.gcm)
                        }
                        .pickerStyle(MenuPickerStyle()) // Dropdown style
                        .onChange(of: viewModel.aesMode) { _, newMode in
                            viewModel.selectedAlgorithm = .aes(keySize: viewModel.selectedKeySize, mode: newMode, processingType: viewModel.selectedAlgorithm.processingType)
                        }
                    }
                }

                // Processing type picker
                HStack(alignment: .center) {
                    Text("Select processing type:")
                        .font(.headline) // Descriptive text for processing type picker
                        .padding(.bottom, 4) // Adds space between text and picker

                    Picker("Processing Type", selection: $viewModel.aesProcessingType) {
                        Text("Faster").tag(ProcressingType.faster)
                        Text("Regular").tag(ProcressingType.regular)
                    }
                    .pickerStyle(MenuPickerStyle()) // Dropdown style
                    .onChange(of: viewModel.aesProcessingType) { _, newProcessingType in
                        viewModel.updateProccessingType(processingType: newProcessingType)
                    }
                }

                // Button to trigger both encryption and decryption
                Button("Encrypt & Decrypt") {
                    viewModel.encryptAndDecrypt()
                }
                .frame( alignment: .center)
                .buttonStyle(.borderedProminent)

                // Display the encrypted text if available
                if !viewModel.encryptedText.isEmpty {
                    Text("Encrypted Text: \(viewModel.encryptedText)")
                        .padding()
                }

                // Display the decrypted text if available
                if !viewModel.decryptedText.isEmpty {
                    Text("Decrypted Text: \(viewModel.decryptedText)")
                        .padding()
                }

                Spacer()
            }
            .padding()
            .onTapGesture {
                // Dismiss the keyboard on tap
                isTextFieldFocused = false
            }

        }
    }
}

// Preview for the ContentView
#Preview {
    ContentView()
}
