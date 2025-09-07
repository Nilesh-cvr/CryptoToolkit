#pragma once
// Copyright (c) 2025 Nilesh Kumar
// Licensed under the MIT License. See LICENSE file in the project root.


#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <limits> 
#include <stdexcept> 
#include <random>

// OpenSSL Headers
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 
#include <openssl/bio.h>
#include <openssl/buffer.h>


#define  OK (0)
#define  EVP_OK (1)
#define  INVALID_INPUT (-1)

#define  RAND_BYTES_FAILED (-2)

#define  EVP_CIPHER_CTX_ERROR (-10)
#define  EVP_CIPHER_INIT_ERROR (-11)
#define  EVP_ENCRYPT_UPDATE_ERROR (-12)
#define  EVP_ENCRYPT_FINAL_ERROR (-13)

std::string Base64Encode(const std::vector<unsigned char>& buffer);
std::vector<unsigned char> Base64Decode(const std::string& encoded);

int EncryptDecryptIV(const unsigned char* plaintext, size_t plaintext_len,const unsigned char* key,
    const unsigned char* iv, std::vector<unsigned char>& out, bool encrypt);

std::vector<unsigned char> SecureRandom(size_t n);

std::string GenerateRandomKey(size_t length);

const EVP_CIPHER* GetCipher();

void handleErrors(void);