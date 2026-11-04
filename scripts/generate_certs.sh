#!/bin/bash
# Certificate generation script for Concurrent TCP Client-Server System
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${1:-$PROJECT_ROOT/certs}"

mkdir -p "$CERTS_DIR"
echo "Generating TLS certificates in: $CERTS_DIR"

CA_KEY="$CERTS_DIR/ca.key"
CA_CRT="$CERTS_DIR/ca.crt"
SERVER_KEY="$CERTS_DIR/server.key"
SERVER_CSR="$CERTS_DIR/server.csr"
SERVER_CRT="$CERTS_DIR/server.crt"
EXT_FILE="$CERTS_DIR/server_ext.cnf"

# 1. Root CA private key
openssl genrsa -out "$CA_KEY" 4096

# 2. Root CA self-signed certificate (valid 10 years)
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CRT" \
    -subj "/C=IN/ST=Uttarakhand/L=Roorkee/O=IIT Roorkee/OU=CSE/CN=SecureFileTransfer Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -addext "subjectKeyIdentifier=hash"

# 3. Server private key
openssl genrsa -out "$SERVER_KEY" 2048

# 4. Server CSR
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
    -subj "/C=IN/ST=Uttarakhand/L=Roorkee/O=IIT Roorkee/OU=CSE/CN=127.0.0.1"

# 5. SAN extension file
cat > "$EXT_FILE" <<EOF
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
IP.3 = ::1
EOF

# 6. Sign Server certificate with Root CA
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SERVER_CRT" -days 730 -sha256 -extfile "$EXT_FILE"

# Clean up
rm -f "$SERVER_CSR" "$EXT_FILE" "$CERTS_DIR/ca.srl"
chmod 600 "$CA_KEY" "$SERVER_KEY"

echo "TLS certificates successfully generated in $CERTS_DIR"
