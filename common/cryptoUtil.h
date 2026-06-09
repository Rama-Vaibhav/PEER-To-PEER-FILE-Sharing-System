#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <string>
#include <vector>

// Hex encoding/decoding helpers
std::string toHex(const std::string &str);
std::string fromHex(const std::string &hex);

// RSA Key Pair Generation
bool generateRSAKeyPair(std::string &outPrivateKeyPEM, std::string &outPublicKeyPEM);
std::string rsaEncrypt(const std::string &plaintext, const std::string &publicKeyPEM);
std::string rsaDecrypt(const std::string &ciphertextHex, const std::string &privateKeyPEM);

// Digital Signature Helpers
std::string signMessage(const std::string &message, const std::string &privateKeyPEM);
bool verifySignature(const std::string &message, const std::string &signatureHex, const std::string &publicKeyPEM);

// AES-256-CBC Symmetric Encryption Helpers
std::vector<char> encryptAES(const std::vector<char> &plaintext, const std::string &keyHex, std::string &outIvHex);
std::vector<char> decryptAES(const std::vector<char> &ciphertext, const std::string &keyHex, const std::string &ivHex);

// AES Key Generation helper
std::string generateAESKey();

#endif // CRYPTO_UTIL_H
