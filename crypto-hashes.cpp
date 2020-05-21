//#include "crypto.h"

#include <iostream>
#include <string>
#include <cstdio>
#include <memory>
using namespace std;

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// #include "encodings.h"


// string hex_encoded (const Ciphertext & ciphertext)
// {
//     return ::hex_encoded (ciphertext.c_str(), ciphertext.length());
// }

string hex_encoded (const unsigned char * s, unsigned int len) {
    const char * const hex_digits = "0123456789abcdef";

    string encoded;
    encoded.reserve (2*len);
    for (unsigned int i = 0; i < len; i++)
    {
        encoded += hex_digits[s[i]/16];
        encoded += hex_digits[s[i]&0xF];
    }

    return encoded;
}

string hashe (const string & text, const EVP_MD * evp_md) {
    unsigned char hash[EVP_MAX_MD_SIZE];

    EVP_MD_CTX ctx;
    unsigned int mdlen;

    EVP_DigestInit (&ctx, evp_md);
    EVP_DigestUpdate (&ctx, reinterpret_cast<const unsigned char *>(text.c_str()), text.length());
    EVP_DigestFinal (&ctx, hash, &mdlen);

    return hex_encoded (hash, mdlen);
}


//************* Hashes (inline forwarder functions) **************

// string md5 (const string & text)
// {
//     return hash (text, EVP_md5());
// }

// string sha1 (const string & text)
// {
//     return hash (text, EVP_sha1());
// }

// string sha224 (const string & text)
// {
//     return hash (text, EVP_sha224());
// }

string sha256 (const string & text)
{
    return hashe (text, EVP_sha256());
}

// string sha384 (const string & text)
// {
//     return hash (text, EVP_sha384());
// }

// string sha512 (const string & text)
// {
//     return hash (text, EVP_sha512());
// }

// namespace
// {
//     string hex_encoded (const unsigned char * s, unsigned int len)
//     {
//         const char * const hex_digits = "0123456789abcdef";

//         string encoded;
//         encoded.reserve (2*len);
//         for (unsigned int i = 0; i < len; i++)
//         {
//             encoded += hex_digits[s[i]/16];
//             encoded += hex_digits[s[i]&0xF];
//         }

//         return encoded;
//     }

//     string hash (const string & text, const EVP_MD * evp_md)
//     {
//         unsigned char hash[EVP_MAX_MD_SIZE];

//         EVP_MD_CTX ctx;
//         unsigned int mdlen;

//         EVP_DigestInit (&ctx, evp_md);
//         EVP_DigestUpdate (&ctx, reinterpret_cast<const unsigned char *>(text.c_str()), text.length());
//         EVP_DigestFinal (&ctx, hash, &mdlen);

//         return hex_encoded (hash, mdlen);
//     }

// } // unnamed namespace

int main (int argc, char * arg[])
{
    // generate challenge

    int byte_count = 16;
    char P[128];
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(&P, 1, byte_count, fp);
    fclose(fp);

    std::cout << "P: "<< P << "\n";
    string s(P);

    std::cout << s.length() << "\n";

    std::cout << sha256(P).length() << "\n";
    
    return 0;
}

