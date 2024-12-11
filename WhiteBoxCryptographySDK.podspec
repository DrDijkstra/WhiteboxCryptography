Pod::Spec.new do |spec|
  spec.name         = "WhiteBoxCryptographySDK"
  spec.version      = "1.0.4"
  spec.summary      = "A cryptographic SDK using white-box cryptography techniques."
  spec.description  = <<-DESC
                      This SDK provides a set of cryptographic functions like AES encryption, decryption, HMAC, and key derivation using PBKDF2.
                  DESC

  spec.homepage     = "https://github.com/DrDijkstra/WhiteboxCryptography"
  spec.license      = { :type => "MIT", :file => "FILE_LICENSE" }

  spec.author             = { "Sanjay Dey" => "deysanjay285@gmail.com" }
  spec.ios.deployment_target = "16.0"
  spec.osx.deployment_target = "12.0"
  spec.watchos.deployment_target = "8.0"
  spec.tvos.deployment_target = "16.0"
  spec.visionos.deployment_target = "1.0"

  spec.source = { :git => 'https://github.com/DrDijkstra/WhiteboxCryptography.git', :tag => spec.version.to_s }

  spec.source_files  = "WhiteBoxCryptography/Sources/**/*.swift"
  spec.swift_versions  = "5.0"

end