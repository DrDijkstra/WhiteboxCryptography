Pod::Spec.new do |spec|
  spec.name         = "WhiteBoxCryptographySDK"
  spec.version      = "1.0.0"
  spec.summary      = "A cryptographic SDK using white-box cryptography techniques."
  spec.description  = <<-DESC
                      This SDK provides a set of cryptographic functions like AES encryption, decryption, HMAC, and key derivation using PBKDF2.
                  DESC

  spec.homepage     = "https://github.com/DrDijkstra/WhiteboxCryptography"
  spec.license = { :type => "MIT", :file => "LICENSE" }


  spec.author             = { "Sanjay Dey" => "deysanjay285@gmail.com" }
  spec.ios.deployment_target = "16.6"
  spec.osx.deployment_target = "15.0"

  spec.source = { :git => 'https://github.com/DrDijkstra/WhiteboxCryptography.git', :tag => spec.version.to_s }

  spec.source_files  = "WhiteBoxCryptography/Sources/**/*.swift"
  spec.swift_versions  = "5.0"

end