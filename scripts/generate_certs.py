#!/usr/bin/env python3
"""
Certificate generation script for Concurrent TCP Client-Server System.
Generates:
  1. ca.key & ca.crt         - Dedicated Root Certificate Authority (CA)
  2. server.key & server.crt - Server Certificate signed by Root CA with SANs
Supports auto-detection of local LAN IPs and custom IP/DNS arguments for multi-machine demos.
"""
import os
import shutil
import socket
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
CERTS_DIR = os.path.join(PROJECT_ROOT, "certs")

def find_openssl():
    which = shutil.which("openssl")
    if which:
        return which
    win_path = r"C:\Program Files\Git\mingw64\bin\openssl.exe"
    if os.path.exists(win_path):
        return win_path
    raise RuntimeError("openssl executable not found in PATH or standard installation directories.")

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error executing: {' '.join(cmd)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

def get_local_ips():
    """Detect local IPv4 addresses so certificates work seamlessly across multiple laptops."""
    ips = set(["127.0.0.1", "0.0.0.0"])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        host_name = socket.gethostname()
        for info in socket.getaddrinfo(host_name, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    return sorted(list(ips))

def generate(certs_dir=None, extra_sans=None):
    if certs_dir is None:
        certs_dir = CERTS_DIR
    os.makedirs(certs_dir, exist_ok=True)
    openssl = find_openssl()

    ca_key = os.path.join(certs_dir, "ca.key")
    ca_crt = os.path.join(certs_dir, "ca.crt")
    server_key = os.path.join(certs_dir, "server.key")
    server_csr = os.path.join(certs_dir, "server.csr")
    server_crt = os.path.join(certs_dir, "server.crt")
    ext_file = os.path.join(certs_dir, "server_ext.cnf")

    # Gather SAN entries
    dns_names = ["localhost", "*.localhost"]
    ip_addrs = get_local_ips()
    if extra_sans:
        for item in extra_sans:
            # Check if item is IP or DNS
            try:
                socket.inet_aton(item)
                if item not in ip_addrs:
                    ip_addrs.append(item)
            except Exception:
                if item not in dns_names:
                    dns_names.append(item)

    print(f"Generating TLS certificates in: {certs_dir}")
    print(f"  Configured SAN IPs:  {', '.join(ip_addrs)}")
    print(f"  Configured SAN DNS:  {', '.join(dns_names)}")

    # 1. Generate Root CA private key (RSA 4096)
    print("Generating Root CA private key...")
    run_cmd([openssl, "genrsa", "-out", ca_key, "4096"])

    # 2. Generate Root CA self-signed certificate (valid 10 years)
    print("Generating Root CA certificate...")
    run_cmd([
        openssl, "req", "-x509", "-new", "-nodes",
        "-key", ca_key,
        "-sha256", "-days", "3650",
        "-out", ca_crt,
        "-subj", "/C=IN/ST=Uttarakhand/L=Roorkee/O=IIT Roorkee/OU=CSE/CN=SecureFileTransfer Root CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        "-addext", "subjectKeyIdentifier=hash"
    ])

    # 3. Generate Server private key (RSA 2048)
    print("Generating Server private key...")
    run_cmd([openssl, "genrsa", "-out", server_key, "2048"])

    # 4. Generate Server CSR
    print("Generating Server CSR...")
    run_cmd([
        openssl, "req", "-new",
        "-key", server_key,
        "-out", server_csr,
        "-subj", "/C=IN/ST=Uttarakhand/L=Roorkee/O=IIT Roorkee/OU=CSE/CN=SecureFileTransfer Server"
    ])

    # 5. Build OpenSSL extension config with all SANs
    alt_lines = []
    for idx, dns in enumerate(dns_names, start=1):
        alt_lines.append(f"DNS.{idx} = {dns}")
    for idx, ip in enumerate(ip_addrs, start=1):
        alt_lines.append(f"IP.{idx} = {ip}")
    alt_lines_str = "\n".join(alt_lines)

    ext_content = f"""basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
{alt_lines_str}
"""
    with open(ext_file, "w") as f:
        f.write(ext_content)

    # 6. Sign the Server Certificate with the Root CA (valid 2 years)
    print("Signing Server certificate with Root CA...")
    run_cmd([
        openssl, "x509", "-req",
        "-in", server_csr,
        "-CA", ca_crt,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", server_crt,
        "-days", "730",
        "-sha256",
        "-extfile", ext_file
    ])

    # Clean up temporary CSR and ext file
    if os.path.exists(server_csr):
        os.remove(server_csr)
    if os.path.exists(ext_file):
        os.remove(ext_file)
    srl_file = os.path.join(certs_dir, "ca.srl")
    if os.path.exists(srl_file):
        os.remove(srl_file)

    try:
        os.chmod(ca_key, 0o600)
        os.chmod(server_key, 0o600)
    except Exception:
        pass

    print(f"Successfully generated:")
    print(f"  CA Certificate:     {ca_crt}")
    print(f"  CA Private Key:     {ca_key}")
    print(f"  Server Certificate: {server_crt}")
    print(f"  Server Private Key: {server_key}")

if __name__ == "__main__":
    out_dir = None
    extra = []
    if len(sys.argv) > 1:
        out_dir = sys.argv[1]
    if len(sys.argv) > 2:
        extra = sys.argv[2:]
    generate(out_dir, extra)
