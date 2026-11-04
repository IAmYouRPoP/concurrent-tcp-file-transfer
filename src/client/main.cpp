#include "menu.hpp"
#include "protocol.hpp"
#include "utils.hpp"
#include "tls_common.hpp"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_SERVER_PORT 1312
#define DEFAULT_SERVER_IP   "127.0.0.1"
#define BUFFER_SIZE         UINT16_MAX

int main(int argc, char* argv[])
{
    std::string server_ip   = DEFAULT_SERVER_IP;
    uint16_t    server_port = DEFAULT_SERVER_PORT;
    std::string ca_file     = "";
    bool        insecure    = false;

    // Parse command line arguments (both positional and options)
    std::vector<std::string> positional_args;
    for(int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if(arg == "--insecure" || arg == "-k")
        {
            insecure = true;
        }
        else if((arg == "--ca") && (i + 1 < argc))
        {
            ca_file = argv[++i];
        }
        else if((arg == "--host" || arg == "-h") && (i + 1 < argc))
        {
            server_ip = argv[++i];
        }
        else if((arg == "--port" || arg == "-p") && (i + 1 < argc))
        {
            server_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        }
        else if(arg == "--help")
        {
            std::cout << "Usage: " << argv[0] << " [options] [host] [port]\n"
                      << "Options:\n"
                      << "  --host <ip>       Server IP or hostname (default: 127.0.0.1)\n"
                      << "  --port <port>     Server port (default: 1312)\n"
                      << "  --ca <ca.crt>     Path to trusted CA certificate\n"
                      << "  -k, --insecure    Disable server TLS certificate validation (insecure)\n"
                      << "  --help            Show this help message\n";
            return EXIT_SUCCESS;
        }
        else if(!arg.empty() && arg[0] != '-')
        {
            positional_args.push_back(arg);
        }
    }

    if(positional_args.size() >= 1)
    {
        server_ip = positional_args[0];
    }
    if(positional_args.size() >= 2)
    {
        server_port = static_cast<uint16_t>(std::atoi(positional_args[1].c_str()));
    }

    // Initialize Client TLS Context
    SSL_CTX* ctx = TLS::create_client_ssl_context(ca_file, insecure);
    if(!ctx)
    {
        std::cerr << "Failed to create client TLS context. Exiting.\n";
        return EXIT_FAILURE;
    }

    int                sock;
    struct sockaddr_in server_addr;
    uint8_t            receive_buffer[BUFFER_SIZE] = {0};
    char               input[1024];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1)
    {
        perror("socket");
        SSL_CTX_free(ctx);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(server_port);
    if(inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        std::cerr << "Invalid server address: " << server_ip << std::endl;
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    std::cout << "Connecting to " << server_ip << ":" << server_port << "..." << std::endl;
    if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("connect");
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    // Perform TLS handshake and certificate verification
    SSL* ssl = TLS::perform_client_handshake(ctx, sock, server_ip, insecure);
    if(!ssl)
    {
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    std::cout << "[Secure TLS Connected] Version: " << SSL_get_version(ssl)
              << " | Cipher: " << SSL_CIPHER_get_name(cipher) << std::endl;

    while(1)
    {
        printf(">>> ");
        if(fgets(input, sizeof(input), stdin) == nullptr)
        {
            break; // End of input (Ctrl+D)
        }
        input[strcspn(input, "\n")] = '\0';
        if(input[0] == '\0')
        {
            continue;
        }
        auto resp = Menu::parse_command_to_packets(input);

        if(!resp.has_value())
        {
            if(strncmp(input, "help", 4) == 0 || strncmp(input, "admin_help ", 10) == 0)
            {
                continue;
            }
            
            printf("%s isn't a valid command\n", input);
            printf("\nFor available commands, type 'help <command>'.\n");
            continue;
        }

        for(auto& packet : resp.value())
        {
            if(!send_all(ssl, &packet, packet.header.total_size))
            {
                perror("send");
                break;
            }
            if(!recv_from_server(ssl, receive_buffer, sizeof(receive_buffer)))
            {
                printf("The connection to the server was lost\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sock);
                SSL_CTX_free(ctx);
                return EXIT_FAILURE;
            }

            if(Menu::handle_response_packet(receive_buffer, ssl))
            {
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return EXIT_SUCCESS;
}
