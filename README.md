<img src="https://raw.githubusercontent.com/DrDijkstra/WhiteboxCryptography/develop/Images/wbc.png" alt="White Box Cryptography Logo" height="150">


# White Box Cryptography Framework

[![Swift](https://img.shields.io/badge/Swift-5.9_5.10_6.0-orange?style=flat-square)](https://img.shields.io/badge/Swift-5.9_5.10_6.0-Orange?style=flat-square)
[![Platforms](https://img.shields.io/badge/Platforms-macOS_iOS_tvOS_watchOS_visionOS-yellowgreen?style=flat-square)](https://img.shields.io/badge/Platforms-macOS_iOS_tvOS_watchOS_visionOS-Green?style=flat-square)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/WhiteboxCryptographySDK.svg?style=flat-square)](https://img.shields.io/cocoapods/v/WhiteboxCryptographySDK.svg)
[![Carthage Compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat-square)](https://github.com/Carthage/Carthage)
[![Swift Package Manager](https://img.shields.io/badge/Swift_Package_Manager-compatible-orange?style=flat-square)](https://img.shields.io/badge/Swift_Package_Manager-compatible-orange?style=flat-square)


A high-performance White Box Cryptography (WBC) framework designed to secure cryptographic keys and operations in a way that prevents attackers from extracting or reverse-engineering them, even when the code and memory are fully exposed. This framework implements cryptographic algorithms in a manner that resists various side-channel and reverse-engineering attacks.

## Features

- **Secure Key Management**: Protects cryptographic keys from extraction or analysis.
- **Encryption Algorithms**: Provides implementations for a variety of cryptographic algorithms in a white-box secure fashion.
- **Side-Channel Attack Resistance**: Built with techniques that prevent leaking sensitive data during execution.
- **Cross-Platform Support**: Compatible with iOS and macOS applications.
- **Optimized Performance**: Designed to provide a balance between security and efficiency.

## Installation

### Using Swift Package Manager (SPM)

To integrate the White Box Cryptography framework into your Xcode project using Swift Package Manager, follow these steps:

1. Open your Xcode project.
2. Go to **File > Swift Packages > Add Package Dependency**.
3. Enter the repository URL for this framework: `https://github.com/DrDijkstra/WhiteboxCryptography`.
4. Choose the version range or tag for the release you want to use.

### Using CocoaPods

1. Add the following to your `Podfile`:

```ruby
pod 'WhiteBoxCryptography', '~> 1.0.1'
```

2. Run `pod install` in the terminal.

3. Open the `.xcworkspace` file in Xcode.

### Using Carthage

To integrate White Box Cryptography with Carthage, add the following to your `Cartfile`:

```
github "DrDijkstra/WhiteboxCryptography" ~> 1.0.1
```

Then run `carthage update` to build the framework.

## Usage

To use the White Box Cryptography framework, simply import it into your project:

```swift
import WhiteBoxCryptography
```

### Example Usage

```swift
// Example of how to use the encryption and decryption functionalities

// Encrypting data
let data = "Sensitive data".data(using: .utf8)!
let encryptedData = WhiteBoxCryptography.encrypt(data: data)

// Decrypting data
let decryptedData = WhiteBoxCryptography.decrypt(data: encryptedData)
let decryptedString = String(data: decryptedData, encoding: .utf8)
print("Decrypted String: \(decryptedString ?? "Failed to decrypt")")
```

### Available Cryptographic Algorithms

The following cryptographic algorithms are available in this implementation:

- **AES** (Advanced Encryption Standard): A symmetric key encryption standard used for securing data.
  - Supports different key sizes (`AESKeySize`) and modes of operation (`AESMode`).
  
- **DES** (Data Encryption Standard): A symmetric-key block cipher, formerly a widely-used method of data encryption.

- **Triple DES** (3DES): An enhancement of DES that applies the DES algorithm three times to each data block.

- **CAST**: A family of symmetric-key block ciphers designed for strong encryption.

- **RC2** (Ron's Code 2): A block cipher designed for use in hardware or software environments, often used for file encryption.

The framework supports encryption, decryption, and hashing for these algorithms in a white-box cryptographic fashion.

## License

This framework is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

## Contributing

We welcome contributions to improve the framework! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a pull request.

## Contact

For questions or support, please contact us at:  
Email: deysanjay121@gmail.com  
GitHub: [https://github.com/DrDijkstra/WhiteboxCryptography](https://github.com/DrDijkstra/WhiteboxCryptography)

