#ifndef CLIENT_TLS_UTILS_H
#define CLIENT_TLS_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

using namespace std;

void init_openssl();
void cleanup_openssl();

// Create client SSL context for connecting to tracker
SSL_CTX* create_tracker_tls_ctx(const char* ca_file);

// Create mTLS context for P2P connections (with client cert)
SSL_CTX* create_mtls_ctx(const char* ca_file, const char* cert_file, const char* key_file);

// TLS I/O helpers
string tls_read_line(SSL* ssl);
bool tls_write_line(SSL* ssl, const string& s);
bool tls_send_all(SSL* ssl, const char* buf, size_t len);
bool tls_recv_exact(SSL* ssl, char* buf, size_t len);

// Save PEM data to file
bool save_pem_to_file(const string& pem_data, const string& filepath);

#endif
