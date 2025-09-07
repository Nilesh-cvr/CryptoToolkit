/*
EVP_CipherInit() is a legacy, allocates & initializes together, limited flexibility, now deprecated.

EVP_CipherInit_ex() = extended to reuse context, supports ENGINEs, better resource control, and is the recommended API in OpenSSL.
*/


/*
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <memory>
#include <limits>


enum {
    OK = 0,
    INVAL = -1,
    EOVERFLOW = -2,
    EVP_ECIPHER_INIT_EX = -10,
    EVP_ECIPHERUPDATE = -11,
    EVP_ECIPHERFINAL_EX = -12,
};

// For a reusable EVP_CIPHER_CTX
class ReusableCipherCtx {
public:
    ReusableCipherCtx()
        : ctx_(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free) {}

    EVP_CIPHER_CTX* get() const { return ctx_.get(); }

    // Reset to a clean state (does NOT free the context)
    void reset() { EVP_CIPHER_CTX_reset(ctx_.get()); }

private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_{EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
};

// Reusable one-shot encrypt/decrypt that does not create/free ctx each time.
// - cipher can be nullptr to keep the previous cipher
// - key/iv can be nullptr to keep the previous key/iv
// - enc: 1=encrypt, 0=decrypt, -1=keep current mode
int EncryptDecryptExReuse(
    ReusableCipherCtx& rctx,
    const EVP_CIPHER* cipher,   // nullptr => keep previous cipher
    int enc,                    // 1 encrypt, 0 decrypt, -1 keep mode
    const unsigned char* key,   // nullptr => keep previous key
    const unsigned char* iv,    // nullptr => keep previous IV/nonce
    const unsigned char* in,
    size_t sz,
    std::vector<unsigned char>& out
) {
    // Basic checks (allow keeping previous key/iv when they are nullptr)
    if ((in == nullptr && sz > 0)) return INVAL;
    if (sz > static_cast<size_t>(std::numeric_limits<int>::max())) return EOVERFLOW;

    // Initialize / re-initialize on the same ctx
    // Passing nullptrs keeps the previous values (cipher/key/iv) as per EVP semantics.
    if (!EVP_CipherInit_ex(rctx.get(), cipher, nullptr, key, iv, enc)) {
        ERR_print_errors_fp(stderr);
        return EVP_ECIPHER_INIT_EX;
    }

    // Allocate output (padding worst-case)
    out.resize(sz + EVP_MAX_BLOCK_LENGTH);

    int outlen1 = 0, outlen2 = 0;
    if (!EVP_CipherUpdate(rctx.get(), out.data(), &outlen1, in, static_cast<int>(sz))) {
        ERR_print_errors_fp(stderr);
        return EVP_ECIPHERUPDATE;
    }

    if (!EVP_CipherFinal_ex(rctx.get(), out.data() + outlen1, &outlen2)) {
        ERR_print_errors_fp(stderr);
        return EVP_ECIPHERFINAL_EX;
    }

    out.resize(outlen1 + outlen2);
    return OK;
}


*/