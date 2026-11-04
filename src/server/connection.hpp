#pragma once

#include "checksum.hpp"
#include "protocol.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <mutex>
#include <openssl/ssl.h>

struct ConnectionWrapper
{
    uint32_t    socket_fd;
    SSL*        ssl = nullptr;
    bool        is_handshake_done = false;
    std::mutex  ssl_mtx;

    uint8_t     buffer[UINT16_MAX];
    uint16_t    buffer_pos = 0;
    std::string current_dir;
    bool        is_admin = false;
    int         fd          = -1; //File that is being uploaded (-1 = none)
    int         download_fd = -1; //File that is being downloaded (-1 = none)
    std::string id;

    //State of an upload that is in progress
    std::string               upload_path;
    uint8_t                   upload_hash[CHECKSUM_LEN] = {};
    std::unique_ptr<Checksum> upload_checksum;

    explicit ConnectionWrapper(uint32_t sock = 0, SSL* ssl_ptr = nullptr)
        : socket_fd(sock), ssl(ssl_ptr) {}

    ~ConnectionWrapper();

    void send_response_sync(uint8_t* buffer, size_t length);

    //Closes an unfinished upload and deletes the half written file
    void abort_upload();

    //Closes the file that was opened for download
    void close_download();

    //Logs the user out: frees the admin slot, closes open files, forgets the user
    void end_session();
};

struct ConnectionBuffer
{
    PacketType get_packet_type();

    //Shared pointer so the connection cannot be destroyed while a worker is still using this packet
    std::shared_ptr<ConnectionWrapper> connection;
    uint8_t                            buffer[UINT16_MAX];
};
