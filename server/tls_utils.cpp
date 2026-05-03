#include "tls_utils.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <sys/select.h>
#include <openssl/bn.h>
using namespace std;

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_server_tls_ctx(const char* cert_file, const char* key_file, const char* ca_file) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Load server private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Load CA cert for verifying client certificates (mTLS)
    if (SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Request client certificate (mTLS) but don't require it for basic client connections
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    return ctx;
}

SSL_CTX* create_client_tls_ctx(const char* ca_file) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    return ctx;
}

// === TLS I/O Helpers ===

string tls_read_line(SSL* ssl) {
    string line;
    char c;
    while (true) {
        int n = SSL_read(ssl, &c, 1);
        if (n <= 0) return string();
        if (c == '\n') break;
        line.push_back(c);
    }
    return line;
}

bool tls_write_line(SSL* ssl, const string& s) {
    string out = s;
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    const char* buf = out.c_str();
    size_t left = out.size();
    while (left > 0) {
        int n = SSL_write(ssl, buf, (int)left);
        if (n <= 0) return false;
        buf += n;
        left -= n;
    }
    return true;
}

bool tls_send_all(SSL* ssl, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

bool tls_recv_exact(SSL* ssl, char* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = SSL_read(ssl, buf + got, (int)(len - got));
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

string tls_read_line_timeout(SSL* ssl, int timeout_seconds) {
    int fd = SSL_get_fd(ssl);
    string line;
    char ch;

    // Check if there's pending data in the SSL buffer first
    if (SSL_pending(ssl) > 0) {
        // Data available in SSL buffer, read without select
        while (true) {
            int n = SSL_read(ssl, &ch, 1);
            if (n <= 0) return string();
            if (ch == '\n') break;
            line.push_back(ch);
        }
        return line;
    }

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        struct timeval tv;
        tv.tv_sec = timeout_seconds;
        tv.tv_usec = 0;

        int rv = select(fd + 1, &readfds, nullptr, nullptr, &tv);
        if (rv == 0) return string("__TIMEOUT__");
        if (rv < 0) return string();

        int n = SSL_read(ssl, &ch, 1);
        if (n <= 0) return string();
        if (ch == '\n') break;
        line.push_back(ch);
    }
    return line;
}

// === On-the-fly Client Certificate Generation ===

bool generate_client_cert(const char* ca_cert_file, const char* ca_key_file,
                          const string& username,
                          string& out_cert_pem, string& out_key_pem) {
    // Load CA cert
    FILE* ca_cert_fp = fopen(ca_cert_file, "r");
    if (!ca_cert_fp) return false;
    X509* ca_cert = PEM_read_X509(ca_cert_fp, nullptr, nullptr, nullptr);
    fclose(ca_cert_fp);
    if (!ca_cert) return false;

    // Load CA private key
    FILE* ca_key_fp = fopen(ca_key_file, "r");
    if (!ca_key_fp) { X509_free(ca_cert); return false; }
    EVP_PKEY* ca_key = PEM_read_PrivateKey(ca_key_fp, nullptr, nullptr, nullptr);
    fclose(ca_key_fp);
    if (!ca_key) { X509_free(ca_cert); return false; }

    // Generate RSA-2048 key pair for the client
    EVP_PKEY* client_key = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    EVP_PKEY_assign_RSA(client_key, rsa);

    // Create X509 certificate
    X509* client_cert = X509_new();
    X509_set_version(client_cert, 2); // v3

    // Random serial number
    ASN1_INTEGER_set(X509_get_serialNumber(client_cert), (long)time(nullptr) + rand());

    // Validity: now to +1 year
    X509_gmtime_adj(X509_get_notBefore(client_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(client_cert), 365 * 24 * 3600);

    // Set subject: CN=<username>
    X509_NAME* name = X509_get_subject_name(client_cert);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"IN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"IIITH", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"P2PSecure", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)username.c_str(), -1, -1, 0);

    // Set issuer from CA cert
    X509_set_issuer_name(client_cert, X509_get_subject_name(ca_cert));

    // Set public key
    X509_set_pubkey(client_cert, client_key);

    // Sign with CA's private key using SHA-256
    X509_sign(client_cert, ca_key, EVP_sha256());

    // Convert cert to PEM string
    BIO* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, client_cert);
    char* cert_data;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    out_cert_pem = string(cert_data, cert_len);

    // Convert key to PEM string
    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, client_key, nullptr, nullptr, 0, nullptr, nullptr);
    char* key_data;
    long key_len = BIO_get_mem_data(key_bio, &key_data);
    out_key_pem = string(key_data, key_len);

    // Cleanup
    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(client_cert);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(client_key);

    return true;
}
