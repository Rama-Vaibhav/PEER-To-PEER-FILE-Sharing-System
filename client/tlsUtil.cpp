#include "client.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

using namespace std;

// Global SSL contexts (defined here, declared extern in client.h)
SSL_CTX* g_clientSSLCtx     = nullptr;   // for connecting to tracker and peers
SSL_CTX* g_peerServerSSLCtx = nullptr;   // for accepting peer chunk requests

void initOpenSSL() {
    // OpenSSL 3.x auto-initializes; this explicit call is a safe no-op on 1.1.0+
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
}

// Create an SSL_CTX for client role (connecting to tracker or to peer servers)
SSL_CTX* initClientSSLCtx(const string& caPath) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        cerr << "[TLS] Failed to create client SSL_CTX" << endl;
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_load_verify_locations(ctx, caPath.c_str(), nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        cerr << "[TLS] Failed to load CA certificate: " << caPath << endl;
        exit(EXIT_FAILURE);
    }

    // Don't enforce strict verification for self-signed certs in dev
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    cout << "\033[32m[TLS] Client SSL context initialized\033[0m" << endl;
    return ctx;
}

// Create an SSL_CTX for the peer server role (accepting chunk download requests)
SSL_CTX* initPeerServerSSLCtx(const string& certPath, const string& keyPath) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        cerr << "[TLS] Failed to create peer server SSL_CTX" << endl;
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cerr << "[TLS] Failed to load peer server certificate: " << certPath << endl;
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cerr << "[TLS] Failed to load peer server private key: " << keyPath << endl;
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        cerr << "[TLS] Peer server private key does not match certificate" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "\033[32m[TLS] Peer server SSL context initialized\033[0m" << endl;
    return ctx;
}

// Wrap accepted socket fd in SSL for server side
SSL* acceptSSL(SSL_CTX* ctx, int clientFd) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_set_fd(ssl, clientFd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}

// Wrap connected socket fd in SSL for client side
SSL* connectSSL(SSL_CTX* ctx, int sockFd) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    SSL_set_fd(ssl, sockFd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return nullptr;
    }
    return ssl;
}
