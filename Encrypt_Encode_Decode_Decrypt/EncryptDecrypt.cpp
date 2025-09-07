// Copyright (c) 2025 Nilesh Kumar
// Licensed under the MIT License. See LICENSE file in the project root.
//Source link reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption 

#include "Encrypt_Encode_Decode_Decrypt.h"


/*EVP_CipherFinal_ex() is a Generic finalizer. Works for either encrypt or decrypt, depending on how the EVP_CIPHER_CTX was initialized with EVP_CipherInit_ex(..., enc=1/0).*/

int EncryptDecryptIV(const unsigned char* plaintext, size_t plaintext_len,const unsigned char* key,
    const unsigned char* iv, std::vector<unsigned char>& ciphertext,bool encrypt){

    if ((iv == nullptr) || (key == nullptr) || (plaintext == nullptr)) {
        return  INVALID_INPUT;
    }

    EVP_CIPHER_CTX* ctx;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
		return EVP_CIPHER_CTX_ERROR;
    }
       
    // Allocate output buffer, ensuring it's large enough for padding
    ciphertext.resize(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    int ciphertext_len1 = 0, ciphertext_len2 = 0;//For encryption, this will add padding. For decryption, this will remove padding and verify it's correct.

    /*
    * Initialise the encryption operation. IMPORTANT - ensure use a key
    * and IV size appropriate for our cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits
    */
    if (EVP_OK != EVP_CipherInit_ex(ctx, GetCipher(), nullptr, key, iv, static_cast<std::uint8_t>(encrypt))) {
        handleErrors();
        return EVP_CIPHER_INIT_ERROR;
    }

	//Guard for plaintext_len before converting size_t into int for OVERFLOW safety.
    if (plaintext_len > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return EOVERFLOW;
    }

    /*
    * Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (EVP_OK != EVP_CipherUpdate(ctx, ciphertext.data(), &ciphertext_len1, plaintext, static_cast<int>(plaintext_len))) {
        handleErrors();
        return EVP_ENCRYPT_UPDATE_ERROR;
    }
    
    /*
    * Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if (EVP_OK != EVP_CipherFinal_ex(ctx, ciphertext.data() + ciphertext_len1, &ciphertext_len2)) {
        handleErrors();
        return EVP_ENCRYPT_FINAL_ERROR;
    }

    ciphertext.resize(ciphertext_len1 + ciphertext_len2); // Resize to actual ciphertext length

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return OK;
} 


/*
int EncryptDecryptNoIV(const unsigned char* plaintext, size_t plaintext_len, unsigned char* key,
    std::vector<unsigned char>& ciphertext, bool encrypt) {

    if ((key == nullptr) || (plaintext == nullptr)) {
        return INVALID_INPUT;
    }

    EVP_CIPHER_CTX* ctx;

    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
        return EVP_CIPHER_CTX_ERROR;
    }

    // Allocate output buffer, ensuring it's large enough for padding
    ciphertext.resize(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    int ciphertext_len1 = 0, ciphertext_len2 = 0;

    
    // Initialise the encryption operation. IMPORTANT - ensure we use a key size appropriate for our cipher. No IV is provided. For demonstration, using AES-256-ECB (no IV required).
   
if (EVP_OK != EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr, static_cast<std::uint8_t>(encrypt))) {
    handleErrors();
    return EVP_CIPHER_INIT_ERROR;
}

// Provide the message to be encrypted/decrypted
if (EVP_OK != EVP_CipherUpdate(ctx, ciphertext.data(), &ciphertext_len1, plaintext, static_cast<int>(plaintext_len))) {
    handleErrors();
    return EVP_ENCRYPT_UPDATE_ERROR;
}

// Finalise the encryption/decryption
if (EVP_OK != EVP_CipherFinal_ex(ctx, ciphertext.data() + ciphertext_len1, &ciphertext_len2)) {
    handleErrors();
    return EVP_ENCRYPT_FINAL_ERROR;
}

ciphertext.resize(ciphertext_len1 + ciphertext_len2); // Resize to actual ciphertext length

// Clean up
EVP_CIPHER_CTX_free(ctx);

return OK;
}

*/


