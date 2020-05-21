#include "crypto.h"

#include <string>
#include <cstdio>
#include <memory>
using namespace std;

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "encodings.h"


namespace cgipp
{

string hex_encoded (const Ciphertext & ciphertext)
{
    return ::hex_encoded (ciphertext.c_str(), ciphertext.length());
}


//******************** Symmetric encryption **********************

const EVP_CIPHER * evp_cipher (Encryption_algorithm cipher)
{
    switch (cipher)
    {
        case AES128_CBC:
            return EVP_aes_128_cbc();

        case AES256_CBC:
            return EVP_aes_256_cbc();

        case DES3_CBC:
            return EVP_des_ede3_cbc();

        case BF_CBC:
            return EVP_bf_cbc();
    }

    return EVP_aes_256_cbc();   // Dummy, just to avoid warning
}


Base_cipher::Base_cipher (const EVP_CIPHER * cipher, const string & key, const string & iv)
    : d_cipher (cipher),
      d_key (key.begin(), key.end()),
      d_iv (iv.begin(), iv.end())
{}

Ciphertext Base_cipher::encrypt (const string & plaintext) const
{
    auto_ptr<unsigned char> ciphertext (new unsigned char [plaintext.length() + EVP_MAX_KEY_LENGTH]);
    int ctlen, extlen;
    EVP_CIPHER_CTX ctx;

    EVP_EncryptInit (&ctx, d_cipher, d_key.c_str(), d_iv.c_str());
    EVP_EncryptUpdate (&ctx, ciphertext.get(), &ctlen,
                       reinterpret_cast<const unsigned char *>(plaintext.c_str()), plaintext.length());
    EVP_EncryptFinal (&ctx, ciphertext.get() + ctlen, &extlen);

    return Ciphertext(ciphertext.get(), ciphertext.get() + ctlen + extlen);
}

string Base_cipher::decrypt (const string & hex_encoded_ciphertext) const
{
    const string & decoded = hex_decoded (hex_encoded_ciphertext);
    return decrypt (Ciphertext (decoded.begin(), decoded.end()));
}

string Base_cipher::decrypt (const Ciphertext & ciphertext) const
{
    auto_ptr<unsigned char> decrypted (new unsigned char [ciphertext.length()]);
    int dlen, extlen;
    EVP_CIPHER_CTX ctx;

    EVP_DecryptInit (&ctx, d_cipher, d_key.c_str(), d_iv.c_str());
    EVP_DecryptUpdate (&ctx, decrypted.get(), &dlen, ciphertext.c_str(), ciphertext.length());
    EVP_DecryptFinal (&ctx, decrypted.get() + dlen, &extlen);

    return string (decrypted.get(), decrypted.get() + dlen + extlen);
}

}   // namespace cgipp
