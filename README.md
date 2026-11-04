# Concurrent TCP Client–Server File Transfer System with TLS

[![Build & Test Status](https://img.shields.io/badge/tests-100%25%20passed-brightgreen.svg)]()
[![TLS](https://img.shields.io/badge/Security-TLS%201.3%20%7C%20TLS%201.2-blue.svg)]()
[![Sanitizers](https://img.shields.io/badge/ASan%2FLSan%2FUBSan-Clean-success.svg)]()
[![C++](https://img.shields.io/badge/C%2B%2B-17%20%2F%2020-orange.svg)]()

A high-performance, secure C++ client–server file management and transfer system built directly on POSIX TCP sockets with non-blocking I/O, a multi-threaded worker pool, SQLite-backed authentication, per-user directory sandboxing, and **end-to-end TLS 1.3 / TLS 1.2 encryption** with strict X.509 certificate validation.

---

## Table of Contents
1. [Architecture & Security Overview](#architecture--security-overview)
2. [Prerequisites & Dependencies](#prerequisites--dependencies)
3. [Repository Structure](#repository-structure)
4. [Certificate Generation](#certificate-generation)
5. [Database & Default Credentials](#database--default-credentials)
6. [Building the Project](#building-the-project)
7. [Running the Server](#running-the-server)
8. [Running the Client](#running-the-client)
9. [Complete Client Command Guide](#complete-client-command-guide)
10. [Admin Monitoring & Management](#admin-monitoring--management)
11. [Cross-Machine / LAN Deployment](#cross-machine--lan-deployment)
12. [Running Automated Tests](#running-automated-tests)
13. [Troubleshooting & Common Pitfalls](#troubleshooting--common-pitfalls)

---

## Architecture & Security Overview

- **Transport Layer Security (TLS 1.3 / 1.2)**:
  - Enforces `TLSv1.3` and `TLSv1.2` via OpenSSL 3.x; all legacy protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) are explicitly disabled.
  - AEAD ciphers only (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384`).
  - Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) for Perfect Forward Secrecy (PFS).
  - CRIME/BREACH mitigation via `SSL_OP_NO_COMPRESSION`.
  - Mutual certificate trust validation against a dedicated X.509 Root CA with Subject Alternative Name (SAN) verification.
- **Framing & Packet Protocol**:
  - Length-delimited custom binary protocol with 4-byte header (`uint16_t command`, `uint16_t total_size`).
  - Maximum packet size of 65,535 bytes with chunked file streaming.
  - End-to-end CRC32 / MD5 checksum verification per chunk and whole file.
- **Concurrency & Scaling**:
  - Non-blocking socket listener and polling loop decoupling network I/O from packet processing.
  - 6-worker thread pool (`ThreadPool`) with thread-safe task queue.
  - Per-connection SSL send mutexes preventing race conditions across concurrent responses.
- **Directory Sandboxing & Isolation**:
  - Every authenticated user is isolated inside an assigned UUID folder under `./tmp/<uuid>`.
  - Strict path sanitization (`is_valid_filename` and directory boundaries) neutralizing Directory Traversal (`../..`) attacks.
  - Mutex-guarded single-admin concurrency locking preventing conflicting administrative actions.

---

## Prerequisites & Dependencies

### Linux / Ubuntu / WSL 2
Install compiler toolchain, CMake, OpenSSL 3.x, SQLite3, and compression libraries:
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    g++ \
    cmake \
    libssl-dev \
    libsqlite3-dev \
    libzstd-dev \
    zlib1g-dev \
    liblzma-dev \
    liblz4-dev \
    libzip-dev \
    python3
```

---

## Repository Structure

```text
custom-concurrent-tcp-protocol/
├── certs/                      # TLS Root CA and Server certificates
│   ├── ca.crt                  # Root Certificate Authority certificate
│   ├── ca.key                  # Root CA private key
│   ├── server.crt              # SAN-enabled server certificate
│   └── server.key              # Server private key
├── scripts/
│   ├── generate_certs.py       # OpenSSL CA and server certificate generator
│   └── generate_certs.sh       # Shell script alternative
├── src/
│   ├── client/                 # Client source code
│   │   ├── main.cpp            # Client entry point and TLS handshake
│   │   ├── menu.hpp            # Interactive CLI parser and command router
│   │   └── packet_controller.hpp
│   ├── server/                 # Server source code
│   │   ├── main.cpp            # Server socket loop, accept thread, thread pool
│   │   ├── client_controller.cpp # Packet dispatch table & command handlers
│   │   ├── connection.cpp      # ConnectionWrapper & thread-safe SSL_write
│   │   ├── database_handler.hpp# SQLite3 authentication logic
│   │   ├── server_info.hpp     # CPU, RAM, and uptime metrics collector
│   │   └── state.hpp           # Global server state, thread pool, mutexes
│   └── common/                 # Shared protocol headers and packet structs
│       ├── constants.hpp       # Global buffer limits, ports, directory paths
│       ├── packets.hpp         # Packet struct definitions
│       ├── protocol.hpp        # PacketType enum definitions
│       └── utils.hpp           # Chunking, CRC/MD5 checksums, path sanitizers
├── tests/
│   ├── test_server.py          # Server functional and regression test suite
│   ├── test_client.py          # Client functional test suite
│   └── pcd.db                  # Pre-populated SQLite authentication database
└── CMakeLists.txt              # CMake build configuration
```

---

## Certificate Generation

The repository comes with pre-generated certificates in `./certs`. To issue fresh certificates (valid for 365 days) with custom IP SANs:

```bash
python3 scripts/generate_certs.py
```
This generates:
- `certs/ca.crt` & `certs/ca.key` (Root CA)
- `certs/server.crt` & `certs/server.key` (Signed by Root CA with SANs for `127.0.0.1`, `localhost`, and local IP)

---

## Database & Default Credentials

User accounts are stored in SQLite database `pcd.db`. Ensure `pcd.db` exists in the directory from which `./server` is executed (e.g. `build/` or `build_asan/`):

```bash
cp tests/pcd.db build_asan/pcd.db
```

### Pre-Configured Accounts:
| Username | Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| `admin` | `admin123` | **Admin** | Full system access (`status`, `connections`, `clean`, `set`, file operations) |
| `bob` | `secret` | **Standard User** | Sandboxed file transfer & directory management |
| `alice` | `pass123` | **Standard User** | Sandboxed file transfer & directory management |

---

## Building the Project

### 1. Release / Standard Build
```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
cd ..
```

### 2. Sanitizer Build (AddressSanitizer + LeakSanitizer + UndefinedBehaviorSanitizer)
Use this build to verify memory safety, zero-leak guarantees, and strict conformance:
```bash
mkdir -p build_asan && cd build_asan
cmake -DCMAKE_BUILD_TYPE=Debug -DSANITIZE=ON ..
make -j$(nproc)
cp ../tests/pcd.db .
cd ..
```

---

## Running the Server

Start the server from the build directory containing `pcd.db` and the certificates:

```bash
cd build_asan
./server -p 9090
```

### Server Command-Line Flags:
- `-p, --port <port>`: Port to listen on (Default: `1312`; **Port `9090` recommended** to avoid Windows Hyper-V port reservations).
- `-c, --cert <path>`: Path to server certificate (Default: `../certs/server.crt` or `certs/server.crt`).
- `-k, --key <path>`: Path to server private key (Default: `../certs/server.key` or `certs/server.key`).
- `-h, --help`: Display command options.

Upon starting, the server prints:
```text
Server listening on port 9090
Worker thread pool initialized with 6 threads.
```

---

## Running the Client

Launch the client from any terminal, specifying server IP and port:

```bash
./build_asan/client <Server_IP> <Port>
```

### Examples:
- **Localhost**:
  ```bash
  ./build_asan/client 127.0.0.1 9090
  ```
- **Remote LAN / Cross-Laptop**:
  ```bash
  ./build_asan/client 10.81.8.215 9090
  ```

Upon connection, the client establishes a strict TLS handshake and displays:
```text
Connecting to 10.81.8.215:9090...
[Secure TLS Connected] Version: TLSv1.3 | Cipher: TLS_AES_256_GCM_SHA384
>>>
```

---

## Complete Client Command Guide

All commands are issued directly into the interactive client prompt (`>>>`).

### 1. Authentication & Session
- **`login <username> <password>`**  
  Authenticates against the SQLite database.  
  *Example:* `login bob secret`  
  *Response:* `Packet: 36` (Logged In).
- **`logout`**  
  Terminates current session, closes open file handles, and releases any held admin locks.
- **`getid`**  
  Prints current session's unique UUID identifier.
- **`ping`**  
  Sends a heartbeat packet to the server.  
  *Response:* `PONG!`

### 2. Directory Navigation & Sandboxing
- **`ls`**  
  Lists all files and subdirectories in the current remote working directory.
- **`mkdir <directory_name>`**  
  Creates a new directory inside the current folder.  
  *Example:* `mkdir documents`
- **`cd <directory_path>`**  
  Changes working directory.  
  *Example:* `cd documents` or `cd ..`
- **Path Traversal Protection (Security Test)**:  
  Attempting to escape your sandboxed user directory is blocked:  
  *Command:* `cd ../../admin` or `rm ../..`  
  *Response:* `Packet: 25` (`IO Error` - Request rejected by path sanitizer).

### 3. File Transfer
- **`upload <local_path_1> [local_path_2 ...]`**  
  Streams one or more local files to the server in chunks, automatically computing and verifying checksums.  
  > [!TIP]  
  > `<local_path>` is resolved relative to the directory where `./client` was launched!  
  *Example from `build/`:* `upload ../demo_files/friend_report.txt`  
  *Example from root:* `upload sample.txt`  
  *Response:* `Packet: 29`, `Packet: 34`, `File transfer was ok!`
- **`download <remote_filename>`**  
  Downloads a file from the server into the client's current directory.  
  *Example:* `download friend_report.txt`

### 4. File Management
- **`cp <source_file> <dest_file>`**  
  Duplicates a file on the server.  
  *Example:* `cp friend_report.txt backup.txt`
- **`mv <source_file> <dest_file>`**  
  Renames or moves a file on the server.  
  *Example:* `mv backup.txt archived_report.txt`
- **`rm <path>`**  
  Permanently deletes a file or empty directory.  
  *Example:* `rm archived_report.txt`

### 5. Multi-Format Compression
Compress files directly on the server. Note that flags must be specified in **UPPERCASE**:
- **Format Options**: `ZSTD` (default), `GZIP`, `XZ`, `LZMA`, `LZ4`, `ZIP`
- **Level Options**: `FASTEST`, `FAST`, `NORMAL` (default), `GOOD`, `BEST`
- **Syntax**:
  ```text
  compress <archive_name> --format <FORMAT> --level <LEVEL> <file1> [file2...]
  ```
  *(Use `*` to compress all files in the current folder)*

#### Examples:
```text
# Compress friend_report.txt using GZIP at FAST level
compress report_archive --format GZIP --level FAST friend_report.txt

# Compress all files using ZSTD at BEST level
compress full_backup --format ZSTD --level BEST *
```
*Note: The server automatically appends the format extension (e.g. `.tar.gz` or `.tar.zst`). Use `ls` to verify the exact generated filename before calling `download`.*

---

## Admin Monitoring & Management

When logged in as `admin` (`login admin admin123`), specialized telemetry commands become available:

- **`status`**  
  Retrieves live server hardware performance and uptime:
  ```text
  packet_size: 40 cpu:0 mem:7.35 uptime:3576
  ```
- **`connections`**  
  Displays active concurrent connections, pending connections, and packet queue backlog:
  ```text
  Packets waiting to be processed: 0    Active connection count: 2    Pending connection count: 0
  ```
- **`get_settings`**  
  Retrieves global server settings (e.g. default compression level).
- **`set COMPRESSION_LEVEL=<1..9>`**  
  Updates global server settings at runtime.
- **`clean`**  
  Wipes all uploaded files and user folders in server temporary storage.

> [!IMPORTANT]  
> **Single-Admin Concurrency Lock**: The server restricts active admin sessions to **1** at any given moment. If a second client attempts `login admin admin123`, the server responds with `Packet: 30 (An admin is already connected!)` until the first admin logs out or disconnects.

---

## Cross-Machine / LAN Deployment

To connect two separate physical machines (e.g., Host Laptop and Friend Laptop):

```text
[Friend Laptop (Laptop 2)]                 [Host Laptop (Laptop 1)]
   Client (Linux/WSL)                          Windows Host (10.81.8.215)
           │                                                │
           │ TLS 1.3 / TCP:9090                             │
           └───────────────────────────────────────────────►│ Port Forward / Proxy
                                                            ▼
                                                       WSL 2 Ubuntu
                                                    Server (:9090)
```

1. **Verify Local LAN IP**:
   Find the Host machine's Wi-Fi / Ethernet IPv4 address (e.g., `10.81.8.215`).
2. **Configure WSL Port Forwarding** (if running server in WSL 2):
   Because WSL 2 runs inside a virtual NAT network, port 9090 on Windows must forward to WSL's internal IP.
   Use the included proxy script:
   ```powershell
   python scratch/wsl_proxy.py
   ```
   *(Or run `netsh interface portproxy add v4tov4 listenport=9090 listenaddress=0.0.0.0 connectport=9090 connectaddress=<WSL_IP>`)*
3. **Connect from Laptop 2**:
   ```bash
   ./client 10.81.8.215 9090
   ```

---

## Running Automated Tests

Run the Python test suites to validate server protocol correctness and sanitizer compliance:

```bash
# Test Server Operations (Authentication, File Transfers, Error Handling)
python3 tests/test_server.py build_asan

# Test Client Operations
python3 tests/test_client.py build_asan
```

Both test suites run headless instances, asserting byte-for-byte fidelity and zero ASan/LSan/UBSan memory leaks.

---

## Troubleshooting & Common Pitfalls

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| `unexpected eof while reading` on port 1312 | Windows Hyper-V / WSL reserves port 1312 under dynamic port exclusions. | Run server and client on port **`9090`** (`./server -p 9090`). |
| `Cannot open the file '<path>'` during upload | The local path is relative to the client's current shell working directory. | If running `./client` from `build/`, use `upload ../demo_files/<file>` or run client from the folder containing the file. |
| `IO Error` (`Packet 25`) during download | The specified filename does not exist on the server. | Run `ls` first to see the exact remote filename (compression appends extensions such as `.tar.zst`). |
| `An admin is already connected!` | A previous client instance logged in as `admin` did not call `logout` or is still running in another tab. | Log out from the other client, or kill the orphaned process (`kill -9 <pid>`). |
| `send: Connection reset by peer` | Idle TCP connection timed out or closed by network proxy. | Ensure network proxy keeps sockets alive without hard timeout limits. |
| `IO Error` on `cd ../..` | Expected behavior! Path traversal protection blocks escaping user sandbox. | Normal operation; users cannot escape their assigned `./tmp/<uuid>` folder. |
