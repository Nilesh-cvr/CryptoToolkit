# CryptoToolkit (Encrypt_Encode_Decode_Decrypt) 
A collection of encryption, decryption, encoding, and decoding utilities demonstrating AES, RSA, Base64, and custom secure data handling, aligned with modern C++ best practices.

🔹About:
This project demonstrates secure data handling in C++ by combining AES-256-CBC encryption/decryption with Base64 encoding/decoding.
It provides a menu-driven interface to explore different workflows:

Encode (Base64)

Decode (Base64)

Direct Encryption → Decryption

Encode → Decode roundtrip

Full pipeline: Encryption → Encode → Decode → Decryption

Built with OpenSSL EVP API, it serves as a practical reference for students, security learners, and developers working on cryptography fundamentals.



🔹Extended Portfolio-Friendly Description:

Encrypt_Encode_Decode_Decrypt is a cross-platform C++ learning project that integrates cryptographic primitives and data encoding into a simple interactive console tool.

🔑 Key Features:

AES-256-CBC encryption/decryption with random IV generation

Base64 encoding/decoding using OpenSSL BIO streams

Verification of round-trip correctness

Modular, menu-driven design for easy testing of each feature

Secure random key generation and proper resource handling (RAII with smart pointers)

📌 Why this project?
This project demonstrates my ability to:

Work with OpenSSL APIs (EVP, BIO, RAND).

Apply RAII principles and manage secure memory.

Design modular, testable C++ applications.

Connect cryptography with real-world practices (payload = IV + ciphertext).


## License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
