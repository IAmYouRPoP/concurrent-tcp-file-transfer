#include <atomic>
#include <cerrno>
#include <csignal>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include "state.hpp"
#include <fcntl.h>
#include <netinet/in.h>
#include "io.hpp"

#include "client_controller.hpp"
#include "protocol.hpp"
#include "tls_common.hpp"

#define DEFAULT_PORT    1312
#define BACKLOG         UINT16_MAX

ServerState g_state;
uint16_t    g_server_port = DEFAULT_PORT;
std::string g_cert_path   = "certs/server.crt";
std::string g_key_path    = "certs/server.key";
std::string g_ca_path     = "";

void handle_packets()
{
    while(!g_state.completed_packets.empty())
    {
        auto p = std::move(g_state.completed_packets.front());
        g_state.completed_packets.pop();

        g_state.thread_pool.dispatch_async([_p = std::move(p)]()
        {
            ClientController::process_packet(std::move(_p));
        });
    }
}

void accept_thread_handler()
{
    int server_socket_fd;
    if((server_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    int reuse = 1;
    setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int));
#endif
    struct sockaddr_in address;
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(g_server_port);
    int address_length = sizeof(address);
    if(bind(server_socket_fd, (struct sockaddr*)&address, address_length) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if(listen(server_socket_fd, BACKLOG) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    g_state.server_socket_fd.exchange(server_socket_fd);

    while(true)
    {
        int client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&address
                , (socklen_t*)&address_length);
        if(client_socket_fd == -1)
        {
            break;
        }
        make_socket_non_blocking(client_socket_fd);

        SSL* ssl = SSL_new(g_state.ssl_ctx);
        if(!ssl)
        {
            close(client_socket_fd);
            continue;
        }
        SSL_set_fd(ssl, client_socket_fd);
        SSL_set_accept_state(ssl);

        auto cw = std::make_shared<ConnectionWrapper>(client_socket_fd, ssl);
        {
            std::lock_guard guard{g_state.pending_connections_mtx};
            g_state.pending_connections.push(std::move(cw));
        }
    }
}

void receive_all_connections()
{
    auto it = g_state.active_connections.begin();

    while(it != g_state.active_connections.end())
    {
        auto& connection = *it;

        std::unique_lock<std::mutex> lock(connection->ssl_mtx, std::try_to_lock);
        if(!lock.owns_lock())
        {
            // A worker thread is currently sending a response via SSL_write.
            // Move on to avoid stalling the network thread.
            ++it;
            continue;
        }

        if(!connection->is_handshake_done)
        {
            ERR_clear_error();
            int ret = SSL_accept(connection->ssl);
            if(ret <= 0)
            {
                int err = SSL_get_error(connection->ssl, ret);
                if((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE) ||
                   ((err == SSL_ERROR_SYSCALL) && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)))
                {
                    ++it;
                    continue;
                }
                // Handshake failed or client disconnected
                lock.unlock();
                it = g_state.active_connections.erase(it);
                continue;
            }
            connection->is_handshake_done = true;
        }

        ERR_clear_error();
        int bytes_read = SSL_read(connection->ssl, connection->buffer + connection->buffer_pos
                , sizeof(connection->buffer) - connection->buffer_pos);

        if(bytes_read <= 0)
        {
            int err = SSL_get_error(connection->ssl, bytes_read);
            if((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE) ||
               ((err == SSL_ERROR_SYSCALL) && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)))
            {
                ++it; // Nothing to read right now
                continue;
            }
            // Lost connection or fatal SSL error
            lock.unlock();
            it = g_state.active_connections.erase(it);
            continue;
        }

        connection->buffer_pos += static_cast<uint16_t>(bytes_read);

        // Read any further pending decrypted bytes buffered inside OpenSSL
        while((connection->buffer_pos < sizeof(connection->buffer)) && (SSL_pending(connection->ssl) > 0))
        {
            ERR_clear_error();
            int more = SSL_read(connection->ssl, connection->buffer + connection->buffer_pos
                    , sizeof(connection->buffer) - connection->buffer_pos);
            if(more <= 0)
            {
                break;
            }
            connection->buffer_pos += static_cast<uint16_t>(more);
        }

        // Cut every complete packet out of the received bytes
        bool bad_packet = false;
        while(connection->buffer_pos >= sizeof(PacketHeader))
        {
            uint16_t packet_size;
            memcpy(&packet_size, connection->buffer + 2, sizeof(packet_size));

            if(packet_size < sizeof(PacketHeader))
            {
                // A packet can never be smaller than its own header: client is broken or hostile
                bad_packet = true;
                break;
            }
            if(connection->buffer_pos < packet_size)
            {
                break; // Wait for the rest of the packet
            }

            auto packet = std::make_shared<ConnectionBuffer>();
            packet->connection = connection;
            memcpy(packet->buffer, connection->buffer, packet_size);
            g_state.completed_packets.push(std::move(packet));

            int delta = connection->buffer_pos - packet_size;
            if(delta > 0)
            {
                memmove(connection->buffer, connection->buffer + packet_size, delta);
            }
            connection->buffer_pos = delta;
        }

        if(bad_packet)
        {
            fprintf(stderr, "Dropping a connection that sent an invalid packet size\n");
            lock.unlock();
            it = g_state.active_connections.erase(it);
            continue;
        }

        ++it;
    }
}

void handle_pending_connections()
{
    std::lock_guard guard{g_state.pending_connections_mtx};

    while(!g_state.pending_connections.empty())
    {
        auto& conn = g_state.pending_connections.top();

        g_state.active_connections.emplace_back(std::move(conn));

        g_state.pending_connections.pop();
    }
}

void server_thread()
{
    for(; g_state.b_should_run.load(std::memory_order_relaxed);)
    {
        // Needs to be run on a separate thread because of while(true)
        receive_all_connections();
        handle_packets();
        handle_pending_connections();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void TerminationRequestHandler(int32_t signal)
{
    if(g_state.b_should_run.exchange(false))
    {
        const auto s = g_state.server_socket_fd.exchange(-1);
        if(s > 0)
        {
            close(s);
            exit(EXIT_SUCCESS);
        }
    }
}

int main(int argc, char* argv[])
{
    (void)::signal(SIGINT, &TerminationRequestHandler);   // Interrupt signal (CTRL + C)
    (void)::signal(SIGTERM, &TerminationRequestHandler);  // Termination request
#ifdef SIGPIPE
    (void)::signal(SIGPIPE, SIG_IGN);                     // Prevent crash on disconnected sockets
#endif

    // Parse command-line options
    for(int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if((arg == "--port" || arg == "-p") && i + 1 < argc)
        {
            g_server_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        }
        else if((arg == "--cert" || arg == "-c") && i + 1 < argc)
        {
            g_cert_path = argv[++i];
        }
        else if((arg == "--key" || arg == "-k") && i + 1 < argc)
        {
            g_key_path = argv[++i];
        }
        else if(arg == "--ca" && i + 1 < argc)
        {
            g_ca_path = argv[++i];
        }
        else if(arg == "--help" || arg == "-h")
        {
            std::cout << "Usage: " << argv[0] << " [options]\n"
                      << "Options:\n"
                      << "  -p, --port <port>   Port to listen on (default: 1312)\n"
                      << "  -c, --cert <file>   TLS certificate file (default: certs/server.crt)\n"
                      << "  -k, --key <file>    TLS private key file (default: certs/server.key)\n"
                      << "  --ca <file>         Optional CA certificate for client verification\n"
                      << "  -h, --help          Show this help message\n";
            return EXIT_SUCCESS;
        }
    }

    mkdir(SERVER_FILES_DIR, 0777);
    srand((unsigned)time(0));
    ClientController::initialize();

    // Initialize TLS server context
    g_state.ssl_ctx = TLS::create_server_ssl_context(g_cert_path, g_key_path, g_ca_path);
    if(!g_state.ssl_ctx)
    {
        std::cerr << "Failed to initialize TLS server context. Please verify certificate paths.\n";
        return EXIT_FAILURE;
    }

    std::cout << "[Secure TCP File Transfer Server]" << std::endl;
    std::cout << "Listening on port: " << g_server_port << " (TLS 1.2+ / TLS 1.3 enforced)" << std::endl;
    std::cout << "Using Certificate: " << g_cert_path << std::endl;

    g_state.thread_pool.start(6);
    auto accept_thread = std::thread(accept_thread_handler);

    server_thread();

    if(g_state.ssl_ctx)
    {
        SSL_CTX_free(g_state.ssl_ctx);
        g_state.ssl_ctx = nullptr;
    }

    return EXIT_SUCCESS;
}
