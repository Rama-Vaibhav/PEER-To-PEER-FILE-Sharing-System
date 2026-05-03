#ifndef TLS_UTILS_H
#define TLS_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string>

using namespace std;

// Initialize OpenSSL library
void init_openssl();
void cleanup_openssl();

// Create server-side SSL context (for tracker accepting clients)
SSL_CTX* create_server_tls_ctx(const char* cert_file, const char* key_file, const char* ca_file);

// Create client-side SSL context (for sync connector to peer tracker)
SSL_CTX* create_client_tls_ctx(const char* ca_file);

// TLS I/O helpers
string tls_read_line(SSL* ssl);
bool tls_write_line(SSL* ssl, const string& s);
bool tls_send_all(SSL* ssl, const char* buf, size_t len);
bool tls_recv_exact(SSL* ssl, char* buf, size_t len);

// Read line with select-based timeout (for sync heartbeats)
string tls_read_line_timeout(SSL* ssl, int timeout_seconds);

// On-the-fly client certificate generation (tracker acts as CA)
// Returns true on success. Writes PEM cert and key into out_cert_pem and out_key_pem.
bool generate_client_cert(const char* ca_cert_file, const char* ca_key_file,
                          const string& username,
                          string& out_cert_pem, string& out_key_pem);

#endif // TLS_UTILS_H
