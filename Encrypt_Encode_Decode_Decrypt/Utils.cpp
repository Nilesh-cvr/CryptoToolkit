// Copyright (c) 2025 Nilesh Kumar
// Licensed under the MIT License. See LICENSE file in the project root.

#include "Encrypt_Encode_Decode_Decrypt.h"

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    return ;
}

const EVP_CIPHER* GetCipher() {
    return EVP_aes_256_cbc();
}

/*Generates cryptographically secure random bytes using OpenSSL's RAND_bytes function. It returns a vector of unsigned char containing the random bytes. If the generation fails, it throws a runtime error.*/
std::vector<unsigned char> SecureRandom(size_t n) {
    std::vector<unsigned char> buf(n);
    if (n && !RAND_bytes(buf.data(), static_cast<int>(n))) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return buf;
}


/*Not used*/
std::string GenerateRandomKey(size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string key;
    for (size_t i = 0; i < length; ++i) {
        key += charset[dist(generator)];
    }
    return key;
}


