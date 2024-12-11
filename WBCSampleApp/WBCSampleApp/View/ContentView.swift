//
//  ContentView.swift
//  WBCSampleApp
//
//  Created by Sanjay Dey on 2024-12-10.
//

import SwiftUI
import Combine

struct ContentView: View {
    
    @StateObject var viewModel: ContentViewModel
    @FocusState private var isInputFocused: Bool
    
    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            
            // Title and description
            Text("White Box Cryptography Sample")
                .font(.largeTitle)
                .bold()
                .foregroundColor(.white)
            
            Text("Enter some text to encrypt and decrypt")
                .font(.subheadline)
                .foregroundColor(.white)
            
            // Text input field
            TextField("Enter text here", text: $viewModel.inputText)
                .frame(height: 44)  // Set the height of the TextField
                .focused($isInputFocused)  // Bind to focus state
                .padding([.horizontal], 8)  // Horizontal padding
                .background(  // Apply background color
                    RoundedRectangle(cornerRadius: 8)  // Set rounded corners for the background
                        .fill(Color.white)  // Set the background color to white
                        .shadow(radius: 5)  // Optional shadow for better visibility
                )
                .overlay(  // Add a border over the rounded corners
                    RoundedRectangle(cornerRadius: 8)  // Rounded corners for the border
                        .stroke(isInputFocused ? Color.green : Color.gray, lineWidth: 1)  // Change border color based on focus state
                )
            
            // Encrypt Button
            Button(action: {
                viewModel.encryptText()
            }) {
                Text("Encrypt")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .padding(.vertical, 8)
                    .background(Color.yellow)
                    .cornerRadius(8)
                    .shadow(radius: 5)
            }
            
            // Encrypted text view
            VStack(alignment: .leading) {
                Text("Encrypted Text:")
                    .font(.headline)
                    .foregroundColor(.white)
                
                Text(viewModel.encryptedText)
                    .font(.body)
                    .foregroundColor(.white)
                    .padding()
                    .background(Color.white.opacity(0.1))
                    .cornerRadius(8)
                    .frame(maxWidth: .infinity)
                    .lineLimit(nil)
            }
            
            // Decrypted text view
            VStack(alignment: .leading) {
                Text("Decrypted Text:")
                    .font(.headline)
                    .foregroundColor(.white)
                
                Text(viewModel.decryptedText)
                    .font(.body)
                    .foregroundColor(.white)
                    .padding()
                    .background(Color.white.opacity(0.1))
                    .cornerRadius(8)
                    .frame(maxWidth: .infinity)
                    .lineLimit(nil)
            }
            
            Spacer()
        }
        .padding()
        .background(LinearGradient(gradient: Gradient(colors: [.purple, .blue]), startPoint: .topLeading, endPoint: .bottomTrailing))
        .edgesIgnoringSafeArea(.all)
        .ignoresSafeArea(.keyboard)
        .simultaneousGesture(TapGesture().onEnded {
            // Dismiss keyboard when tapping outside of the TextField
            isInputFocused = false
        })
        
    }
}

#Preview {
    ContentView(viewModel: ContentViewModel())
}
