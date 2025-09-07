// Copyright (c) 2025 Nilesh Kumar
// Licensed under the MIT License. See LICENSE file in the project root.

#include "Encrypt_Encode_Decode_Decrypt.h"

std::string Base64Encode(const std::vector<unsigned char>& buffer) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines in output
    BIO_write(bio, buffer.data(), static_cast<int>(buffer.size()));
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<unsigned char> Base64Decode(const std::string& encoded) {
    BIO* bio, * b64;
    int decodeLen = static_cast<int>(encoded.length());
    std::vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), decodeLen);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, buffer.data(), decodeLen);

    if (len > 0) {
        buffer.resize(len);
    }
    else {
        buffer.clear();
    }

    BIO_free_all(bio);
    return buffer;
}