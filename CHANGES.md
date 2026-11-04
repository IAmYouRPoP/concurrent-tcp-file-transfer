# Changes in this version

## Security & Transport Layer Security (TLS) Integration
- **End-to-End TLS Encryption**: All network traffic between client and server is encrypted using TLS 1.3 / TLS 1.2 with OpenSSL. Plaintext transmission of credentials and file contents is eliminated.
- **Protocol Enforcement & Cipher Selection**: Obsolete/insecure protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are rejected. Strict modern AEAD ciphers (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `ECDHE-ECDSA/RSA-AES-GCM`) with Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) provide Perfect Forward Secrecy.
- **Certificate Verification & SANs**: The client strictly verifies the server certificate against a trusted Certificate Authority (CA) and validates Subject Alternative Names (SANs) for hostname/IP matching to prevent Man-in-the-Middle (MITM) attacks.
- **Non-blocking Asynchronous TLS Engine**: TLS handshake (`SSL_accept`) and stream reception (`SSL_read`) are fully non-blocking and integrated into the server's main network thread.
- **Thread Safety**: Multi-threaded access to `SSL*` between worker threads (`send_response_sync`) and the network reception thread is protected by fine-grained per-connection locking (`ssl_mtx`) with `try_to_lock` to avoid blocking the event loop.
- **Certificate Automation**: Included `scripts/generate_certs.py` and `scripts/generate_certs.sh` to generate Root CA and server certificates with SANs for development, testing, and production deployment.
- **Configurable CLI Parameters**: Server and client support `--port`, `--cert`, `--key`, `--ca`, and `--insecure` flags.

## Build
- CMake configuration updated to link `OpenSSL::SSL` alongside `OpenSSL::Crypto`.
- If `src/libs/sqlite3.c` exists it is compiled in, otherwise the installed SQLite (`libsqlite3-dev`) is used.
- `cmake -DSANITIZE=ON ..` builds with AddressSanitizer + UndefinedBehaviorSanitizer (LeakSanitizer is included).

## Empty / unfinished parts that are now finished
- **File checksum (MD5)** for upload and download. The empty `REQ_CRC_VERIFY` handler is gone; the checksum is now sent in the upload start packet (`hash` field) and in the download info packet, and is checked automatically. A damaged upload is deleted by the server and answered with `RESP_CRC_FAILED`; a damaged download is deleted by the client.
- `status` now shows the CPU use of the last 100 ms (before: average since the machine started).

## Bugs fixed
Security
- `rm ..` / `rm .` deleted the folders of **all** users. Names `""`, `.` and `..` are now refused everywhere.
- `compress` accepted `../` in file and archive names (could read/write other users' files) and a `file_count` bigger than the array (read past the end). Both are checked now.
- `cp`/`mv`: the "inside the user folder" check compares whole folder names now (it compared only the start of the text).
- Text fields from the network are no longer assumed to end with `\0`.
- A packet whose size field was smaller than the 4 byte header could crash the server. The connection is dropped now.
- Unknown commands, or response types sent as a request, crashed a worker thread (`bad_function_call`). They get `RESP_IO_ERROR` now, and every handler runs inside try/catch.
- `MSG_NOSIGNAL` on `send` and `SIGPIPE` ignore handler prevent unexpected daemon termination on broken sockets.

Crashes / wrong behaviour
- A packet could be used after its connection was already destroyed (packets now keep the connection alive; the socket is closed in the destructor).
- File descriptors started at `0` (= stdin) and could be closed twice. They start at `-1` now and are reset after closing.
- Upload: `open()` was not checked, `write()` result was ignored, uploading a smaller file over a bigger one left old bytes at the end, an unfinished upload left a half file. All fixed.
- Download: after an error the server sent two replies; the file was opened read/write; the client never closed the server file; an existing longer local file kept its old tail.
- Empty file upload and uploading a missing file are fixed.
- Logout did not reset `is_admin`; logging in again on the same connection is handled.
- Worker threads read the connection's live buffer instead of their own packet copy (`get_packet_type`, `set`).
- Packets are given to the workers in arrival order (queue instead of stack).
- Client: pressing Enter on an empty line repeated the previous command; the client spun forever when the server closed the connection; `Packet` structs were sent with uninitialised bytes.
- `SO_REUSEADDR` was given an uninitialised value; `socket()` result was compared with `== 0`.

## Tests
- `python3 tests/test_server.py build_asan` (63 checks, sends real packets over encrypted TLS, including attacks)
- `python3 tests/test_client.py build_asan` (13 checks, uses the real client over TLS)
