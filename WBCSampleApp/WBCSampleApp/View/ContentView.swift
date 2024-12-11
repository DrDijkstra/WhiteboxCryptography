//
//  ContentView.swift
//  WBCSampleApp
//
//  Created by Sanjay Dey on 2024-12-10.
//

import SwiftUI

struct ContentView: View {
    @StateObject var viewModel: ContentViewModel
    
    // Detects when the user taps anywhere on the screen to dismiss the keyboard
    @FocusState private var isInputFocused: Bool
    
    var body: some View {
        VStack {
            Spacer()
            
            // Title and description
            Text("White Box Cryptography Sample")
                .font(.largeTitle)
                .bold()
                .padding(.bottom, 20)
            
            Text("Enter some text to encrypt and decrypt")
                .font(.subheadline)
                .padding(.bottom, 10)
            
            // Text input field
            TextField("Enter text here", text: $viewModel.inputText)
                .padding()
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .frame(width: 300)
                .focused($isInputFocused) // Bind to focus state
            
            Spacer()
            
            // Encrypt Button
            Button(action: {
                viewModel.encryptText()
            }) {
                Text("Encrypt")
                    .font(.headline)
                    .foregroundColor(.white)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(8)
            }
            
            Spacer()
            
            // Encrypted text view
            Text("Encrypted Text:")
                .font(.headline)
                .padding(.top, 20)
            Text(viewModel.encryptedText)
                .font(.body)
                .padding()
                .background(Color.gray.opacity(0.1))
                .cornerRadius(8)
                .frame(width: 300)
            
            // Decrypted text view
            Text("Decrypted Text:")
                .font(.headline)
                .padding(.top, 20)
            Text(viewModel.decryptedText)
                .font(.body)
                .padding()
                .background(Color.gray.opacity(0.1))
                .cornerRadius(8)
                .frame(width: 300)
            
            Spacer()
        }
        .padding()
        .background(LinearGradient(gradient: Gradient(colors: [.purple, .blue]), startPoint: .topLeading, endPoint: .bottomTrailing))
        .edgesIgnoringSafeArea(.all)
        .simultaneousGesture(TapGesture().onEnded {
            // Dismiss keyboard when tapping outside of the TextField
            isInputFocused = false
        })
    }
}

#Preview {
    ContentView(viewModel: ContentViewModel())
}
