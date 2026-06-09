#include "tracker.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace std;

// Generate a 16-byte random salt and return it as a 32-char hex string
string generateSalt() {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        cerr << "[Security] RAND_bytes failed, falling back to weak random" << endl;
        // Fallback — not cryptographically secure but better than nothing
        for (int i = 0; i < 16; ++i) raw[i] = (unsigned char)(rand() % 256);
    }
    ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << hex << setw(2) << setfill('0') << (int)raw[i];
    }
    return oss.str();
}

// Hash password with salt using SHA-256: SHA256(salt + password) → 64-char hex string
string hashPassword(const string& password, const string& salt) {
    string input = salt + password;
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), md);

    ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << hex << setw(2) << setfill('0') << (int)md[i];
    }
    return oss.str();
}
