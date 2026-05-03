#!/bin/bash
# generate_certs.sh — Generate PKI certificates for Secure P2P File Sharing
# Creates: CA cert, tracker server cert, and a template for client certs
set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAYS=3650  # 10 years validity
RSA_BITS=2048

echo "=== Generating PKI Certificates ==="
echo "Output directory: $CERT_DIR"

# 1. Generate CA (Certificate Authority) key and self-signed cert
echo "[1/3] Generating CA certificate..."
openssl genrsa -out "$CERT_DIR/ca.key" $RSA_BITS 2>/dev/null
openssl req -new -x509 -days $DAYS -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=IN/ST=Telangana/L=Hyderabad/O=IIITH/OU=P2PSecure/CN=P2P-CA" 2>/dev/null
echo "    ✓ ca.key, ca.crt"

# 2. Generate Tracker server key and CA-signed cert
echo "[2/3] Generating Tracker server certificate..."
openssl genrsa -out "$CERT_DIR/tracker.key" $RSA_BITS 2>/dev/null
openssl req -new -key "$CERT_DIR/tracker.key" \
    -out "$CERT_DIR/tracker.csr" \
    -subj "/C=IN/ST=Telangana/L=Hyderabad/O=IIITH/OU=P2PSecure/CN=tracker" 2>/dev/null
openssl x509 -req -days $DAYS -in "$CERT_DIR/tracker.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/tracker.crt" 2>/dev/null
rm -f "$CERT_DIR/tracker.csr"
echo "    ✓ tracker.key, tracker.crt"

# 3. Generate a default client key pair (for initial testing)
echo "[3/3] Generating default client certificate..."
openssl genrsa -out "$CERT_DIR/client_default.key" $RSA_BITS 2>/dev/null
openssl req -new -key "$CERT_DIR/client_default.key" \
    -out "$CERT_DIR/client_default.csr" \
    -subj "/C=IN/ST=Telangana/L=Hyderabad/O=IIITH/OU=P2PSecure/CN=client" 2>/dev/null
openssl x509 -req -days $DAYS -in "$CERT_DIR/client_default.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client_default.crt" 2>/dev/null
rm -f "$CERT_DIR/client_default.csr"
echo "    ✓ client_default.key, client_default.crt"

echo ""
echo "=== PKI Certificate Chain ==="
echo "  CA (root):     ca.crt / ca.key"
echo "  Tracker:       tracker.crt / tracker.key  (signed by CA)"
echo "  Client:        client_default.crt / client_default.key  (signed by CA)"
echo ""
echo "All certificates generated successfully!"
