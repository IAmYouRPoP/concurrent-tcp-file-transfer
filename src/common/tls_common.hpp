#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <arpa/inet.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <memory>
#include <vector>

namespace TLS {

// Strict modern TLS cipher configuration:
// TLS 1.3 AEAD-only suites
inline const char* const TLS13_CIPHERS = 
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

// TLS 1.2 Perfect Forward Secrecy + AEAD suites (disables CBC, RC4, 3DES, static RSA)
inline const char* const TLS12_CIPHERS = 
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";

// Print OpenSSL error stack with custom context label
inline void log_ssl_errors(const std::string& context_label)
{
    char err_buf[256];
    unsigned long err_code;
    while((err_code = ERR_get_error()) != 0)
    {
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "[" << context_label << "] OpenSSL Error: " << err_buf << std::endl;
    }
}

// Helper to resolve certificate file paths intelligently across working directories
inline std::string resolve_cert_path(const std::string& file_name)
{
    if(file_name.empty())
    {
        return "";
    }

    // 1. Direct path check
    if(std::filesystem::exists(file_name))
    {
        return file_name;
    }

    std::string base = std::filesystem::path(file_name).filename().string();

    std::vector<std::filesystem::path> candidates = {
        std::filesystem::path("certs") / base,
        std::filesystem::path("..") / "certs" / base,
        std::filesystem::path("..") / ".." / "certs" / base,
        std::filesystem::path("..") / file_name,
        std::filesystem::path("..") / ".." / file_name,
        std::filesystem::path(base)
    };

    for(const auto& candidate : candidates)
    {
        if(std::filesystem::exists(candidate))
        {
            return candidate.string();
        }
    }

    return file_name;
}

// Initializes a hardened server SSL_CTX
inline SSL_CTX* create_server_ssl_context(
    const std::string& cert_file,
    const std::string& key_file,
    const std::string& ca_file = "")
{
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if(!ctx)
    {
        log_ssl_errors("Server SSL_CTX_new");
        return nullptr;
    }

    // Enforce TLS 1.2 minimum version (preferring TLS 1.3)
    if(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
    {
        log_ssl_errors("Server SSL_CTX_set_min_proto_version");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Hardened security flags:
    // - Disable insecure legacy protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    // - Disable TLS compression (mitigates CRIME attack)
    // - Prefer server cipher ordering
    // - Single DH/ECDH key use to guarantee forward secrecy per connection
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
                 | SSL_OP_NO_COMPRESSION
                 | SSL_OP_CIPHER_SERVER_PREFERENCE
                 | SSL_OP_SINGLE_DH_USE
                 | SSL_OP_SINGLE_ECDH_USE;
#ifdef SSL_OP_NO_RENEGOTIATION
    options |= SSL_OP_NO_RENEGOTIATION;
#endif
    SSL_CTX_set_options(ctx, options);

    // Apply strict modern cipher suites
    if(SSL_CTX_set_ciphersuites(ctx, TLS13_CIPHERS) != 1)
    {
        log_ssl_errors("Server SSL_CTX_set_ciphersuites");
    }
    if(SSL_CTX_set_cipher_list(ctx, TLS12_CIPHERS) != 1)
    {
        log_ssl_errors("Server SSL_CTX_set_cipher_list");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Enable automatic Elliptic Curve selection for PFS (X25519 / P-256)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_ecdh_auto(ctx, 1);
#endif

    // Load server certificate chain
    std::string actual_cert = resolve_cert_path(cert_file);
    if(SSL_CTX_use_certificate_chain_file(ctx, actual_cert.c_str()) <= 0)
    {
        std::cerr << "Error: Could not load server certificate from: " << actual_cert << std::endl;
        log_ssl_errors("Server certificate load");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Load server private key
    std::string actual_key = resolve_cert_path(key_file);
    if(SSL_CTX_use_PrivateKey_file(ctx, actual_key.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error: Could not load server private key from: " << actual_key << std::endl;
        log_ssl_errors("Server private key load");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Verify certificate and private key match
    if(!SSL_CTX_check_private_key(ctx))
    {
        std::cerr << "Error: Private key does not match public certificate!" << std::endl;
        log_ssl_errors("SSL_CTX_check_private_key");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Optional CA file
    if(!ca_file.empty())
    {
        std::string actual_ca = resolve_cert_path(ca_file);
        if(std::filesystem::exists(actual_ca))
        {
            if(SSL_CTX_load_verify_locations(ctx, actual_ca.c_str(), nullptr) <= 0)
            {
                log_ssl_errors("Server CA load");
            }
        }
    }

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    return ctx;
}

// Initializes a hardened client SSL_CTX with strict verification
inline SSL_CTX* create_client_ssl_context(
    const std::string& ca_file = "",
    bool insecure = false)
{
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if(!ctx)
    {
        log_ssl_errors("Client SSL_CTX_new");
        return nullptr;
    }

    // Enforce TLS 1.2 minimum version
    if(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1)
    {
        log_ssl_errors("Client SSL_CTX_set_min_proto_version");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
                 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, options);

    SSL_CTX_set_ciphersuites(ctx, TLS13_CIPHERS);
    SSL_CTX_set_cipher_list(ctx, TLS12_CIPHERS);

    if(insecure)
    {
        std::cerr << "[WARNING] Certificate verification disabled (--insecure). "
                  << "Connection is vulnerable to MITM attacks!" << std::endl;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    else
    {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

        bool ca_loaded = false;
        std::string actual_ca = ca_file.empty() ? resolve_cert_path("ca.crt") : resolve_cert_path(ca_file);
        if(std::filesystem::exists(actual_ca))
        {
            if(SSL_CTX_load_verify_locations(ctx, actual_ca.c_str(), nullptr) > 0)
            {
                ca_loaded = true;
            }
            else
            {
                std::cerr << "Warning: Failed to load specified CA file: " << actual_ca << std::endl;
                log_ssl_errors("Client CA load");
            }
        }

        if(!ca_loaded)
        {
            // Fall back to system trusted CA store
            SSL_CTX_set_default_verify_paths(ctx);
        }
    }

    return ctx;
}

// Connect and verify TLS handshake on client socket
inline SSL* perform_client_handshake(
    SSL_CTX* ctx,
    int socket_fd,
    const std::string& host,
    bool insecure)
{
    SSL* ssl = SSL_new(ctx);
    if(!ssl)
    {
        log_ssl_errors("SSL_new");
        return nullptr;
    }

    SSL_set_fd(ssl, socket_fd);

    if(!insecure)
    {
        // Server Name Indication (SNI)
        SSL_set_tlsext_host_name(ssl, host.c_str());

        // Hostname / IP address verification
        X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

        struct in_addr addr4;
        struct in6_addr addr6;
        if(inet_pton(AF_INET, host.c_str(), &addr4) == 1 || inet_pton(AF_INET6, host.c_str(), &addr6) == 1)
        {
            X509_VERIFY_PARAM_set1_ip_asc(param, host.c_str());
        }
        else
        {
            X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.length());
        }
    }

    int ret = SSL_connect(ssl);
    if(ret <= 0)
    {
        long verify_err = SSL_get_verify_result(ssl);
        if(verify_err != X509_V_OK)
        {
            std::cerr << "TLS Connection Failed: Certificate verification error: "
                      << X509_verify_cert_error_string(verify_err) << std::endl;
            std::cerr << "Tip: Ensure the server certificate was issued by your trusted CA." << std::endl;
            std::cerr << "     Specify your CA file with --ca <path/to/ca.crt>." << std::endl;
            std::cerr << "     For development testing only, use --insecure to bypass verification." << std::endl;
        }
        else
        {
            std::cerr << "TLS Handshake failed (SSL_connect error: " << SSL_get_error(ssl, ret) << ")." << std::endl;
            log_ssl_errors("SSL_connect");
        }
        SSL_free(ssl);
        return nullptr;
    }

    return ssl;
}

} // namespace TLS
