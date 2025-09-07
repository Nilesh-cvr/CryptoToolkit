// Copyright (c) 2025 Nilesh Kumar
// Licensed under the MIT License. See LICENSE file in the project root.
//Source link reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption 


#include "Encrypt_Encode_Decode_Decrypt.h"

// 1) Encode
void ActionEncode() {
    std::string input;
    std::cout << "Enter the plain text to Base64-Encode: ";
    std::getline(std::cin, input);

    std::vector<unsigned char> bytes(input.begin(), input.end());
    std::string b64 = Base64Encode(bytes);
    std::cout << "Base64 Encoded: " << b64 << std::endl;
}

// 2) Decode
void ActionDecode() {
    std::string b64;
    std::cout << "Enter the Base64 string to Decode: ";
    std::getline(std::cin, b64);

    auto decoded = Base64Decode(b64);
    std::string out(decoded.begin(), decoded.end());
    std::cout << "Decoded Text: \"" << out << "\"" << std::endl;
    std::cout << "Decoded Bytes: " << decoded.size() << std::endl;
}

// 3) Encryption -> Decryption (direct AES roundtrip, no Base64)
void ActionEncryptDecryptDirect() {
   
    //1. Generate a random Symmetric key for Encryption and Decryption.We can convert into Base64 if needed.
    size_t key_length = 32;
    auto randmKey = SecureRandom(key_length);

    if (randmKey.size() != 32) {
        std::cerr << "Fatal: Key is not 32 bytes long for AES-256." << std::endl;
        return;
    }

    // 2) Input
    std::string plaintext;
    std::cout << "Enter the String to Encrypt (direct roundtrip): ";
    std::getline(std::cin, plaintext);
    std::cout << "\nOriginal Plaintext = \"" << plaintext << "\"" << std::endl;

    // 3) Random IV
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (!RAND_bytes(iv.data(), (int)iv.size())) {
        std::cerr << "Error: Failed to generate random IV." << std::endl;
        return;
    }

    // 4) Encrypt
    std::vector<unsigned char> encrypted;
    int enc_result = EncryptDecryptIV(
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.size(),
        randmKey.data(),
        iv.data(),
        encrypted,
		true //encrypt
    );
    if (enc_result != OK) {
        std::cerr << "Encryption failed with code: " << enc_result << std::endl;
        return;
    }
    std::cout << "Encryption successful, Encrypted data =  " << encrypted.data() << std::endl;

    // 5) Decrypt (no Base64 in this option)
    std::vector<unsigned char> decrypted;
    int dec_result = EncryptDecryptIV(
        encrypted.data(),
        encrypted.size(),
        randmKey.data(),
        iv.data(),
        decrypted,
		false // decrypt
    );
    if (dec_result != OK) {
        std::cerr << "Decryption failed with code: " << dec_result << std::endl;
        return;
    }

    std::string recovered(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    std::cout << "Decryption successful.\nDecrypted Text = \"" << recovered << "\"" << std::endl;
    std::cout << ((recovered == plaintext) ? "\nVerification Successful \n"
        : "\nVerification Failed \n");
}

// 4) Encode -> Decode (roundtrip)
void ActionEncodeDecodeRoundtrip() {
    std::string input;
    std::cout << "Enter the String to Encode then Decode: ";
    std::getline(std::cin, input);

    std::vector<unsigned char> bytes(input.begin(), input.end());
    std::string b64 = Base64Encode(bytes);
    auto decoded = Base64Decode(b64);
    std::string out(decoded.begin(), decoded.end());

    std::cout << "Base64 Encoded: " << b64 << std::endl;
    std::cout << "Decoded Text: \"" << out << "\"" << std::endl;
    std::cout << ((out == input) ? "\nVerification Successful\n"
        : "\nVerification Failed \n");
}

// 5) Encryption -> Encode -> Decode -> Decryption 
void ActionEncryptEncodeDecodeDecrypt() {
    // 1. Generate a secure random key (32 bytes for AES-256)
    size_t key_length = 32;
   
	// 2. Generate a random Symmetric key for Encryption and Decryption.We can convert into Base64 if needed.
    auto randmKey = SecureRandom(key_length);


    if (randmKey.size() != 32) {
        std::cerr << "Fatal: Key is not 32 bytes long for AES-256." << std::endl;
        return;
    }

    std::string plaintext;
    std::cout << "Enter the String to Encrypt and Encode: ";
    std::getline(std::cin, plaintext);
    std::cout << "\nOriginal Plaintext = \"" << plaintext << "\"" << std::endl;

    // --- ENCRYPTION ---
    std::vector<unsigned char> encrypted;
    std::string b64_encoded_payload;

    try {
        // 1. Random IV (16 bytes) per encryption
        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        if (!RAND_bytes(iv.data(), (int)iv.size())) {
            throw std::runtime_error("Failed to generate random IV.");
        }

        // 2. Encrypt the plaintext
        int enc_result = EncryptDecryptIV(
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            plaintext.size(),
            randmKey.data(),
            iv.data(),
            encrypted,
			true // encrypt
        );

        if (enc_result != OK) {
            throw std::runtime_error("Encryption failed with code: " + std::to_string(enc_result));
        }

        // 3. Prepend IV to ciphertext
        std::vector<unsigned char> payload;
        payload.reserve(iv.size() + encrypted.size());
        payload.insert(payload.end(), iv.begin(), iv.end());
        payload.insert(payload.end(), encrypted.begin(), encrypted.end());

        // 4. Base64 encode (IV + ciphertext)
        b64_encoded_payload = Base64Encode(payload);

        std::cout << "Encryption successful." << std::endl;
        std::cout << "Base64 Encoded Payload (IV + Ciphertext) = " << b64_encoded_payload << std::endl;

    }
    catch (const std::exception& e) {
        std::cerr << "Error during encryption: " << e.what() << std::endl;
        return;
    }

    // --- DECRYPTION ---
    std::cout << "\n--- Starting Decryption Process ---" << std::endl;

    try {
        // 1. Base64 decode the payload
        std::vector<unsigned char> decoded_payload = Base64Decode(b64_encoded_payload);
        if (decoded_payload.size() < AES_BLOCK_SIZE) {
            throw std::runtime_error("Decoded payload is smaller than IV size.");
        }

        // 2. Extract IV
        std::vector<unsigned char> iv(decoded_payload.begin(), decoded_payload.begin() + AES_BLOCK_SIZE);

        // 3. Extract ciphertext
        std::vector<unsigned char> ciphertext(decoded_payload.begin() + AES_BLOCK_SIZE, decoded_payload.end());

        // 4. Decrypt
        std::vector<unsigned char> decrypted;
        int dec_result = EncryptDecryptIV(
            ciphertext.data(),
            ciphertext.size(),
            randmKey.data(),
            iv.data(),
            decrypted,
            false // decrypt
        );

        if (dec_result != OK) {
            throw std::runtime_error("Decryption failed with code: " + std::to_string(dec_result));
        }

        std::string decrypted_text(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        std::cout << "Decryption successful." << std::endl;
        std::cout << "Decrypted Text = \"" << decrypted_text << "\"" << std::endl;

        // Verification
        if (plaintext == decrypted_text) {
            std::cout << "\nVerification Successful: Original plaintext matches decrypted text." << std::endl;
        }
        else {
            std::cout << "\nVerification Failed: Mismatch between original and decrypted text." << std::endl;
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error during decryption: " << e.what() << std::endl;
        return;
    }
}


// MENU
void ShowMenu() {
    std::cout << "\n=============================================\n";
    std::cout << " 1) Encode (Base64)\n";
    std::cout << " 2) Decode (Base64)\n";
    std::cout << " 3) Encryption -> Decryption (AES-256-CBC, direct)\n";
    std::cout << " 4) Encode -> Decode (roundtrip)\n";
    std::cout << " 5) Encryption -> Encode -> Decode -> Decryption (original pipeline)\n";
    std::cout << " 0) Exit\n";
    std::cout << "=============================================\n";
    std::cout << "Choose option: ";
}

int main() {

    ERR_load_crypto_strings();

    while (true) {
        ShowMenu();
        int option;
        if (!(std::cin >> option)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input, try again.\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // consume newline

        switch (option) {
        case 1: ActionEncode(); break;
        case 2: ActionDecode(); break;
        case 3: ActionEncryptDecryptDirect(); break;
        case 4: ActionEncodeDecodeRoundtrip(); break;
        case 5: ActionEncryptEncodeDecodeDecrypt(); break;
        case 0:
            std::cout << "Exiting...\n";
            //ERR_free_strings(); //With OpenSSL ≥1.1.0, error strings are auto-loaded; explicit load/free is unnecessary.
            return 0;
        default:
            std::cout << "Unknown option. Try again.\n";
        }
    }
}
