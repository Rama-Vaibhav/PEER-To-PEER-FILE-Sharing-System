#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstddef>  
#include <fcntl.h>
#include <unistd.h>

using namespace std;

string sha1_hex_buffer(const unsigned char *buf, size_t len) {
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA1(buf, len, md);
    ostringstream oss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        oss << hex << setw(2) << setfill('0') << (int)md[i];
    }
    return oss.str();
}

// Stream the file and return SHA-1 hex (lowercase). Empty string on error.
string sha1_hex_of_file(const string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return {};

    SHA_CTX ctx;              // OpenSSL SHA1 context
    SHA1_Init(&ctx);

    vector<unsigned char> buf(1024 * 1024); // 1MB chunks
    while (true) {
        ssize_t n = read(fd, buf.data(), buf.size());
        if (n < 0) { close(fd); return {}; }     // read error
        if (n == 0) break;                       // EOF
        SHA1_Update(&ctx, buf.data(), (size_t)n);
    }
    close(fd);

    unsigned char md[SHA_DIGEST_LENGTH];
    SHA1_Final(md, &ctx);

    // hex encode (lowercase)
    static const char* HEX = "0123456789abcdef";
    string out; out.resize(SHA_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        out[2*i]   = HEX[(md[i] >> 4) & 0xF];
        out[2*i+1] = HEX[(md[i])      & 0xF];
    }
    return out;
}
