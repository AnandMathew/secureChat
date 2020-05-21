#ifndef CGIPP_CRYPTO_H
#define CGIPP_CRYPTO_H

#include <string>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

namespace cgipp
{

using std::string;
using std::basic_string;

typedef std::basic_string<unsigned char> Ciphertext;

string hex_encoded (const Ciphertext & ciphertext);

enum Encryption_algorithm
{
    AES128_CBC,
    AES256_CBC,
    DES3_CBC,
    BF_CBC
};

const EVP_CIPHER * evp_cipher (Encryption_algorithm cipher);

class Base_cipher
{
public:
    Base_cipher (const EVP_CIPHER * cipher, const string & key, const string & iv = string(EVP_MAX_IV_LENGTH, '\0'));

    Ciphertext encrypt (const string & plaintext) const;

    string decrypt (const string & hex_encoded_ciphertext) const;
    string decrypt (const Ciphertext & ciphertext) const;

private:
    const EVP_CIPHER * d_cipher;
    basic_string<unsigned char> d_key;
    basic_string<unsigned char> d_iv;
};

template <Encryption_algorithm cipher = AES256_CBC>
class Generic_cipher : public Base_cipher
{
public:
    Generic_cipher (const string & key, const string & iv = string(EVP_MAX_IV_LENGTH, '\0'))
        : Base_cipher (evp_cipher(cipher), key, iv)
    {}
};


typedef Generic_cipher<AES256_CBC> Cipher;

}   // namespace cgipp

#endif
