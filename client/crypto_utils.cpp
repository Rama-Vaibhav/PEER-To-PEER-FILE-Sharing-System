#include "crypto_utils.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <iostream>
using namespace std;

string hex_encode(const unsigned char* data, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << setw(2) << (int)data[i];
    return ss.str();
}

bool hex_decode(const string& hex, unsigned char* out, size_t* out_len) {
    if (hex.size() % 2 != 0) return false;
    *out_len = hex.size() / 2;
    for (size_t i = 0; i < *out_len; ++i) {
        unsigned int byte;
        sscanf(hex.c_str() + 2 * i, "%02x", &byte);
        out[i] = (unsigned char)byte;
    }
    return true;
}

bool generate_rsa_keypair(string& out_public_pem, string& out_private_pem) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    if (!rsa) return false;
    EVP_PKEY_assign_RSA(pkey, rsa);

    // Private key to PEM
    BIO* priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* priv_data;
    long priv_len = BIO_get_mem_data(priv_bio, &priv_data);
    out_private_pem = string(priv_data, priv_len);

    // Public key to PEM
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, pkey);
    char* pub_data;
    long pub_len = BIO_get_mem_data(pub_bio, &pub_data);
    out_public_pem = string(pub_data, pub_len);

    BIO_free(priv_bio);
    BIO_free(pub_bio);
    EVP_PKEY_free(pkey);
    return true;
}

string rsa_sign(const string& private_key_pem, const string& data) {
    BIO* bio = BIO_new_mem_buf(private_key_pem.c_str(), (int)private_key_pem.size());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        cerr << "[CRYPTO] Failed to load private key for signing\n";
        return "";
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, data.c_str(), data.size());

    unsigned int sig_len = 0;
    unsigned char sig_buf[512]; // RSA-2048 signature is 256 bytes
    EVP_SignFinal(ctx, sig_buf, &sig_len, pkey);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return hex_encode(sig_buf, sig_len);
}

bool rsa_verify(const string& public_key_pem, const string& data, const string& hex_signature) {
    BIO* bio = BIO_new_mem_buf(public_key_pem.c_str(), (int)public_key_pem.size());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        cerr << "[CRYPTO] Failed to load public key for verification\n";
        return false;
    }

    unsigned char sig_buf[512];
    size_t sig_len;
    if (!hex_decode(hex_signature, sig_buf, &sig_len)) {
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, data.c_str(), data.size());
    int result = EVP_VerifyFinal(ctx, sig_buf, (unsigned int)sig_len, pkey);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return (result == 1);
}
