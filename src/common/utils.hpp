#pragma once
#include "checksum.hpp"
#include "packets.hpp"
#include "protocol.hpp"
#include "tls_common.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>
#include <chrono>
#include <thread>

//Reads exactly "count" bytes from the secure TLS stream. Returns false if connection lost.
inline bool recv_all(SSL* ssl, uint8_t* buffer, size_t count)
{
    size_t received = 0;
    while(received < count)
    {
        int bytes_read = SSL_read(ssl, buffer + received, static_cast<int>(count - received));
        if(bytes_read <= 0)
        {
            int err = SSL_get_error(ssl, bytes_read);
            if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            return false;
        }
        received += static_cast<size_t>(bytes_read);
    }
    return true;
}

//Receives one complete packet (header first, then the rest) over TLS into "buffer".
inline bool recv_from_server(SSL* ssl, uint8_t* buffer, size_t length)
{
    if(!recv_all(ssl, buffer, sizeof(PacketHeader)))
    {
        return false;
    }

    uint16_t packet_size;
    memcpy(&packet_size, buffer + 2, sizeof(packet_size));
    if((packet_size < sizeof(PacketHeader)) || (packet_size > length))
    {
        fprintf(stderr, "The server sent an invalid packet\n");
        return false;
    }

    return recv_all(ssl, buffer + sizeof(PacketHeader), packet_size - sizeof(PacketHeader));
}

//Sends all "count" bytes over secure TLS stream. Returns false on error.
inline bool send_all(SSL* ssl, const void* buffer, size_t count)
{
    size_t sent = 0;
    while(sent < count)
    {
        int bytes_sent = SSL_write(ssl, reinterpret_cast<const uint8_t*>(buffer) + sent, static_cast<int>(count - sent));
        if(bytes_sent <= 0)
        {
            int err = SSL_get_error(ssl, bytes_sent);
            if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            return false;
        }
        sent += static_cast<size_t>(bytes_sent);
    }
    return true;
}

//Reads exactly "count" bytes from the socket. Returns false if the connection is lost.
inline bool recv_all(uint32_t socket, uint8_t* buffer, size_t count)
{
    size_t received = 0;
    while(received < count)
    {
        ssize_t bytes_read = recv(socket, buffer + received, count - received, 0);
        if(bytes_read == 0)
        {
            return false; //The server closed the connection
        }
        if(bytes_read < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            perror("lost connection");
            return false;
        }
        received += static_cast<size_t>(bytes_read);
    }
    return true;
}

//Receives one complete packet (header first, then the rest) into "buffer".
inline bool recv_from_server(uint32_t socket, uint8_t* buffer, size_t length)
{
    if(!recv_all(socket, buffer, sizeof(PacketHeader)))
    {
        return false;
    }

    uint16_t packet_size;
    memcpy(&packet_size, buffer + 2, sizeof(packet_size));
    if((packet_size < sizeof(PacketHeader)) || (packet_size > length))
    {
        fprintf(stderr, "The server sent an invalid packet\n");
        return false;
    }

    return recv_all(socket, buffer + sizeof(PacketHeader), packet_size - sizeof(PacketHeader));
}

inline std::vector<uint8_t> read_entire_file(const char* path)
{
    std::ifstream file(path, std::ios::binary);
    if(!file.is_open())
    {
        throw std::runtime_error(std::string("cannot open file ") + path);
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();

    return data;
}

inline std::vector<std::vector<uint8_t>> break_vector_into(uint16_t size, std::vector<uint8_t> data)
{
    std::vector<std::vector<uint8_t>> result;

    size_t dataSize  = data.size();
    size_t num_vecs  = dataSize / size;
    size_t remaining = dataSize % size;

    for(size_t i = 0; i < num_vecs; ++i)
    {
        result.push_back(std::vector<uint8_t>(data.begin() + i * size, data.begin() + (i + 1) * size));
    }

    if(remaining > 0)
    {
        result.push_back(std::vector<uint8_t>(data.begin() + num_vecs * size, data.end()));
    }

    return result;
}


//TODO: Refactor the way packets are made and sent to be faster and stream the packets instead of loading everything into memory
//Builds the packets for one upload: START (name + checksum), then CHUNKs, and the last one is END.
//Returns an empty list (and prints why) if the file cannot be read.
std::vector<Packet> create_file_transfer_packets(const char* file_path, uint16_t chunk_size)
{
    std::vector<uint8_t> file_content;
    try
    {
        file_content = read_entire_file(file_path);
    }
    catch(const std::exception&)
    {
        printf("Cannot open the file '%s'\n", file_path);
        return {};
    }

    auto file_chunks = break_vector_into(chunk_size, file_content);

    //Checksum of the whole file, so the server can check that it arrived without damage
    Checksum checksum;
    checksum.update(file_content.data(), file_content.size());

    std::vector<Packet> packets;

    //Only the file name is sent (not the folders in front of it): the server accepts plain names only
    std::string base_name = std::filesystem::path(file_path).filename().string();

    Packet                  start_packet{};
    PacketTransferFileStart& start = *reinterpret_cast<PacketTransferFileStart*>(&start_packet);
    start.header.command    = PacketType::REQ_FILE_TRANSFER_START;
    start.header.total_size = sizeof(PacketTransferFileStart);
    strncpy(start.file_name, base_name.c_str(), sizeof(start.file_name) - 1);
    checksum.finish(start.hash);
    packets.push_back(start_packet);

    for(auto& chunk : file_chunks)
    {
        Packet p{};
        p.header.total_size = sizeof(PacketHeader) + chunk.size();

        p.header.command = PacketType::REQ_FILE_TRANSFER_CHUNK;
        memcpy(p.buffer, chunk.data(), chunk.size());
        packets.push_back(p);
    }

    if(file_chunks.empty())
    {
        //Empty file: there is no data, but the server still needs the END packet
        Packet end_packet{};
        end_packet.header.command    = PacketType::REQ_FILE_TRANSFER_END;
        end_packet.header.total_size = sizeof(PacketHeader);
        packets.push_back(end_packet);
    }
    else
    {
        packets.back().header.command = PacketType::REQ_FILE_TRANSFER_END;
    }

    return packets;
}
