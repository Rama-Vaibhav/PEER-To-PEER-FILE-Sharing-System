#include "tls_utils.h"
#include <iostream>
#include <fstream>
#include <cstring>
using namespace std;

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_tracker_tls_ctx(const char* ca_file) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); return nullptr; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    return ctx;
}

SSL_CTX* create_mtls_ctx(const char* ca_file, const char* cert_file, const char* key_file) {
    const SSL_METHOD* method = TLS_method();  // acts as both client and server
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); return nullptr; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load CA cert for verifying peers
    if (SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Load our certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Load our private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Require and verify peer certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    return ctx;
}

// === TLS I/O helpers ===

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

bool save_pem_to_file(const string& pem_data, const string& filepath) {
    ofstream out(filepath, ios::trunc);
    if (!out.is_open()) return false;
    out << pem_data;
    out.close();
    return true;
}
