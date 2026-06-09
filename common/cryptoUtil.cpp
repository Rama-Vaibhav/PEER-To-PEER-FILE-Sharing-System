#include "cryptoUtil.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace std;

std::string toHex(const std::string &str) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : str) {
        ss << std::setw(2) << (int)c;
    }
    return ss.str();
}

std::string fromHex(const std::string &hex) {
    std::string result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 >= hex.length()) break;
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

bool generateRSAKeyPair(std::string &outPrivateKeyPEM, std::string &outPublicKeyPEM) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048);
    if (!pkey) {
        cerr << "[Crypto] Failed to generate RSA key pair" << endl;
        return false;
    }

    // Write Private Key to PEM
    BIO *bioPriv = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bioPriv, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
        BIO_free(bioPriv);
        EVP_PKEY_free(pkey);
        return false;
    }
    char *privData;
    long privLen = BIO_get_mem_data(bioPriv, &privData);
    outPrivateKeyPEM = string(privData, privLen);
    BIO_free(bioPriv);

    // Write Public Key to PEM
    BIO *bioPub = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(bioPub, pkey) <= 0) {
        BIO_free(bioPub);
        EVP_PKEY_free(pkey);
        return false;
    }
    char *pubData;
    long pubLen = BIO_get_mem_data(bioPub, &pubData);
    outPublicKeyPEM = string(pubData, pubLen);
    BIO_free(bioPub);

    EVP_PKEY_free(pkey);
    return true;
}

std::string signMessage(const std::string &message, const std::string &privateKeyPEM) {
    BIO *bio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        cerr << "[Crypto] Sign: failed to parse private key" << endl;
        return "";
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    size_t sigLen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    vector<unsigned char> sig(sigLen);
    if (EVP_DigestSignFinal(ctx, sig.data(), &sigLen) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return toHex(string((char*)sig.data(), sigLen));
}

bool verifySignature(const std::string &message, const std::string &signatureHex, const std::string &publicKeyPEM) {
    string signature = fromHex(signatureHex);
    BIO *bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        cerr << "[Crypto] Verify: failed to parse public key" << endl;
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int ret = EVP_DigestVerifyFinal(ctx, (unsigned char*)signature.data(), signature.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret == 1;
}

std::vector<char> encryptAES(const std::vector<char> &plaintext, const std::string &keyHex, std::string &outIvHex) {
    string key = fromHex(keyHex);
    if (key.size() != 32) {
        cerr << "[Crypto] Encrypt: Invalid key size (expected 32 bytes)" << endl;
        return {};
    }

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) <= 0) {
        cerr << "[Crypto] Encrypt: Failed to generate random IV" << endl;
        return {};
    }
    outIvHex = toHex(string((char*)iv, sizeof(iv)));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), iv) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    vector<char> ciphertext(plaintext.size() + 16);
    int len = 0;
    if (EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<char> decryptAES(const std::vector<char> &ciphertext, const std::string &keyHex, const std::string &ivHex) {
    string key = fromHex(keyHex);
    string iv = fromHex(ivHex);
    if (key.size() != 32 || iv.size() != 16) {
        cerr << "[Crypto] Decrypt: Invalid key or IV size" << endl;
        return {};
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), (unsigned char*)iv.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    vector<char> plaintext(ciphertext.size());
    int len = 0;
    if (EVP_DecryptUpdate(ctx, (unsigned char*)plaintext.data(), &len, (unsigned char*)ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        cerr << "[Crypto] Decrypt: padding verification/decryption failed" << endl;
        return {};
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return plaintext;
}

std::string generateAESKey() {
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) <= 0) {
        return "";
    }
    return toHex(string((char*)key, sizeof(key)));
}

std::string rsaEncrypt(const std::string &plaintext, const std::string &publicKeyPEM) {
    BIO* bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        cerr << "[Crypto] RSA Encrypt: Failed to parse public key" << endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (unsigned char*)plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    vector<unsigned char> out(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, (unsigned char*)plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return toHex(string((char*)out.data(), outlen));
}

std::string rsaDecrypt(const std::string &ciphertextHex, const std::string &privateKeyPEM) {
    string ciphertext = fromHex(ciphertextHex);
    BIO* bio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        cerr << "[Crypto] RSA Decrypt: Failed to parse private key" << endl;
        return "";
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, (unsigned char*)ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    vector<unsigned char> out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, (unsigned char*)ciphertext.data(), ciphertext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return string((char*)out.data(), outlen);
}


