#!/bin/bash
# ==============================================================================
# Generate self-signed CA + server certificates for the P2P system.
# Both tracker and peer servers use the same server cert for simplicity.
# ==============================================================================

set -e

CERTS_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CERTS_DIR"

echo "[*] Generating self-signed CA..."
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout ca.key -out ca.crt \
    -subj "/C=IN/ST=Dev/L=Local/O=P2P-CA/CN=P2P-Root-CA" \
    2>/dev/null

echo "[*] Generating server key + CSR..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -subj "/C=IN/ST=Dev/L=Local/O=P2P-Server/CN=localhost" \
    2>/dev/null

# Create a SAN extension file so the cert covers localhost and 127.0.0.1
cat > san.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
IP.2  = 0.0.0.0
EOF

echo "[*] Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 3650 \
    -extfile san.ext \
    2>/dev/null

# Cleanup temporaries
rm -f server.csr san.ext ca.srl

echo "[✓] Certificates generated in $CERTS_DIR:"
ls -la ca.crt ca.key server.crt server.key
echo ""
echo "  ca.crt      — CA certificate (load on clients for verification)"
echo "  ca.key      — CA private key (keep safe, not needed at runtime)"
echo "  server.crt  — Server certificate (load on tracker + peer servers)"
echo "  server.key  — Server private key (load on tracker + peer servers)"
