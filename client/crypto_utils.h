#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
using namespace std;

// Generate RSA-2048 key pair, returns PEM-encoded strings
bool generate_rsa_keypair(string& out_public_pem, string& out_private_pem);

// Sign data with RSA-2048 private key (SHA-256 digest), returns hex-encoded signature
string rsa_sign(const string& private_key_pem, const string& data);

// Verify RSA-2048 signature, returns true if valid
bool rsa_verify(const string& public_key_pem, const string& data, const string& hex_signature);

// Hex encode/decode helpers
string hex_encode(const unsigned char* data, size_t len);
bool hex_decode(const string& hex, unsigned char* out, size_t* out_len);

#endif
