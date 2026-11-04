#include "connection.hpp"
#include "constants.hpp"
#include "state.hpp"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

ConnectionWrapper::~ConnectionWrapper()
{
    end_session();
    if(ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }
    if(socket_fd != (uint32_t)-1)
    {
        close(socket_fd);
        socket_fd = (uint32_t)-1;
    }
}

void ConnectionWrapper::abort_upload()
{
    if(fd >= 0)
    {
        close(fd);
        fd = -1;
        if(!upload_path.empty())
        {
            std::remove(upload_path.c_str());
        }
    }
    upload_path.clear();
    upload_checksum.reset();
}

void ConnectionWrapper::close_download()
{
    if(download_fd >= 0)
    {
        close(download_fd);
        download_fd = -1;
    }
}

void ConnectionWrapper::end_session()
{
    if(is_admin)
    {
        std::cout << "An admin disconnected!\n";
        g_state.b_admin_connected.exchange(false);
        is_admin = false;
    }
    abort_upload();
    close_download();
    id.clear();
    current_dir.clear();
}

void ConnectionWrapper::send_response_sync(uint8_t* buffer, size_t length)
{
    std::lock_guard<std::mutex> lock(ssl_mtx);
    if(!ssl)
    {
        return;
    }

    size_t sent_bytes = 0;
    int    waited_ms  = 0;

    while(sent_bytes < length)
    {
        ERR_clear_error();
        int result = SSL_write(this->ssl, buffer + sent_bytes, static_cast<int>(length - sent_bytes));
        if(result <= 0)
        {
            int err = SSL_get_error(this->ssl, result);
            if((err == SSL_ERROR_WANT_WRITE) || (err == SSL_ERROR_WANT_READ) ||
               ((err == SSL_ERROR_SYSCALL) && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)))
            {
                //Give up if the client does not read for 30 seconds
                if(++waited_ms > 30000)
                {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            // Fatal SSL send error or client closed connection
            return;
        }
        waited_ms = 0;
        sent_bytes += static_cast<size_t>(result);
    }
}

PacketType ConnectionBuffer::get_packet_type()
{
    //Use this packet's own copy of the bytes (not the connection's live receive buffer)
    return static_cast<PacketType>(buffer[1]);
}
