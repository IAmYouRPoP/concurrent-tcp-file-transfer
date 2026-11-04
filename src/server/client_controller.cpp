#include "client_controller.hpp"
#include "checksum.hpp"
#include "constants.hpp"
#include "packets.hpp"
#include "packets_utils.hpp"
#include "protocol.hpp"
#include "sqlite3.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "db_handler.hpp"
#include "state.hpp"
#include "io.hpp"
#include "compression_controller.hpp"
#include <filesystem>
#include <iostream>

std::function<void(std::shared_ptr<ConnectionBuffer>)>
ClientController::handlers[UINT8_MAX + 1];

void ClientController::initialize()
{
    set_handler<PacketType::REQ_SERVER_STATUS>(
        [](std::shared_ptr<ConnectionBuffer> cb)
    {
        if(!cb->connection->is_admin)
        {
            send_resp_not_admin(cb, tls_buffer);
            return;
        }

        create_server_status_packet(tls_buffer);

        cb->connection->send_response_sync(tls_buffer
        , sizeof(ServerStatusPacket));
    });


    handlers[(int)PacketType::REQ_CONNECTIONS_INFO]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            if(!cb->connection->is_admin)
            {
                send_resp_not_admin(cb, tls_buffer);
                return;
            }

            create_connections_info_packet(tls_buffer);

            cb->connection->send_response_sync(tls_buffer
                , sizeof(PacketConnectionsInfo));
        };

    handlers[(int)PacketType::REQ_LOGOUT]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            //Frees the admin slot, closes open files and forgets the user
            cb->connection->end_session();
            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };

    handlers[(int)PacketType::REQ_CURRENT_DIRECTORY]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            create_current_dir_packet(cb->connection->current_dir, tls_buffer);
            cb->connection->send_response_sync(tls_buffer
                , sizeof(PacketCurrentDirectory));
        };

    handlers[(int)PacketType::REQ_REMOVE_PATH]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto&       in_packet = *reinterpret_cast<PacketRemovePath*>(cb->buffer);
            std::string name      = field_to_string(in_packet.path);
            if(!is_valid_filename(name.c_str()))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }
            auto path = cb->connection->current_dir + '/' + name;
            if(remove_file(path.c_str()) || remove_directory(path.c_str()))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
                return;
            }
            send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
        };

    handlers[(int)PacketType::REQ_MKDIR]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto&       in_packet = *reinterpret_cast<PacketMakeDirectory*>(cb->buffer);
            std::string name      = field_to_string(in_packet.path);
            if(!is_valid_filename(name.c_str()))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }
            auto path = cb->connection->current_dir + '/' + name;

            if(mkdir(path.c_str(), 0777) != 0)
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };

    handlers[(int)PacketType::REQ_CHANGE_WORKING_DIRECTORY]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto& packet = *reinterpret_cast<PacketChangeCurrentDirectory*>(cb->buffer);

            std::string new_dir = cd_command(cb->connection->current_dir, field_to_string(packet.path));
            if(new_dir.empty())
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }
            cb->connection->current_dir = new_dir;
            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };

    handlers[(int)PacketType::REQ_FILE_OPEN]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto&       in_packet = *reinterpret_cast<PacketDownloadFile*>(cb->buffer);
            auto&       conn      = *cb->connection;
            std::string name      = field_to_string(in_packet.path);

            if(!is_valid_filename(name.c_str()))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            conn.close_download(); //In case an earlier download was never closed

            std::string file_path = conn.current_dir + '/' + name;
            int         file      = open(file_path.c_str(), O_RDONLY);
            if(file < 0)
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            struct stat file_stat;
            uint8_t     hash[CHECKSUM_LEN];
            if((fstat(file, &file_stat) != 0) || !S_ISREG(file_stat.st_mode)
                || !checksum_of_file(file_path.c_str(), hash))
            {
                close(file);
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            off_t    file_size      = file_stat.st_size;
            uint16_t max_chunk_size = UINT16_MAX - sizeof(PacketHeader);
            size_t   chunk_count    = (file_size / max_chunk_size) + (file_size % max_chunk_size != 0);

            conn.download_fd = file;

            create_chunk_info_packet(tls_buffer, chunk_count, name.c_str(), hash);
            conn.send_response_sync(tls_buffer, sizeof(PacketDownloadedFileInfo));
        };

    handlers[(int)PacketType::REQ_FILE_DOWNLOAD_CHUNK]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto& in_packet = *reinterpret_cast<PacketDownloadChunk*>(cb->buffer);
            auto& conn      = *cb->connection;

            if((conn.download_fd < 0)
                || (create_chunk_packet(tls_buffer, in_packet.chunk_index, conn.download_fd) < 0))
            {
                conn.close_download();
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }
            auto& out_packet = *reinterpret_cast<PacketTransferFileChunk*>(tls_buffer);

            conn.send_response_sync(tls_buffer, out_packet.header.total_size);
        };

    handlers[(int)PacketType::REQ_FILE_CLOSE]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            cb->connection->close_download();
            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };

    handlers[(int)PacketType::REQ_MOVE_FILE]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto& in_packet = *reinterpret_cast<PacketMoveFile*>(cb->buffer);

            std::string first  = field_to_string(in_packet.first_path);
            std::string second = field_to_string(in_packet.second_path);
            if(first.empty() || second.empty())
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            auto user_dir = std::string(SERVER_FILES_DIR) + '/' + cb->connection->id;

            fs::path user_dir_path    = fs::weakly_canonical(user_dir);
            fs::path current_dir_path = fs::weakly_canonical(cb->connection->current_dir);

            fs::path source      = fs::weakly_canonical(current_dir_path / first);
            fs::path destination = fs::weakly_canonical(current_dir_path / second);

            if(!is_path_within_user_dir(source, user_dir_path) || !is_path_within_user_dir(destination, user_dir_path)
                || (source == user_dir_path))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            if(!move_file(source, destination))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };

    handlers[(int)PacketType::REQ_COPY_FILE]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto& in_packet = *reinterpret_cast<PacketCopyFile*>(cb->buffer);

            std::string first  = field_to_string(in_packet.first_path);
            std::string second = field_to_string(in_packet.second_path);
            if(first.empty() || second.empty())
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            auto user_dir = std::string(SERVER_FILES_DIR) + '/' + cb->connection->id;

            fs::path user_dir_path    = fs::weakly_canonical(user_dir);
            fs::path current_dir_path = fs::weakly_canonical(cb->connection->current_dir);

            fs::path source      = fs::weakly_canonical(current_dir_path / first);
            fs::path destination = fs::weakly_canonical(current_dir_path / second);

            if(!is_path_within_user_dir(source, user_dir_path) || !is_path_within_user_dir(destination, user_dir_path)
                || (source == user_dir_path))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            if(!copy_path(source, destination))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };


    handlers[(int)PacketType::REQ_PING]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            send_sample_resp(cb, tls_buffer, PacketType::RESP_PONG);
        };

    handlers[(int)PacketType::REQ_GET_CURRENT_USER]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            create_current_user_packet(cb->connection->id, tls_buffer);
            cb->connection->send_response_sync(tls_buffer
                , sizeof(PacketCurrentUser));
        };

    handlers[(int)PacketType::REQ_FILE_TRANSFER_START]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto&       in_packet = *reinterpret_cast<PacketTransferFileStart*>(cb->buffer);
            auto&       conn      = *cb->connection;
            std::string name      = field_to_string(in_packet.file_name);

            conn.abort_upload(); //Forget (and delete) an earlier upload that never finished

            if(!is_valid_filename(name.c_str()))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            std::string file_path = conn.current_dir + '/' + name;
            //O_TRUNC: uploading over an existing file replaces it completely
            int file = open(file_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if(file < 0)
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            conn.fd              = file;
            conn.upload_path     = file_path;
            conn.upload_checksum = std::make_unique<Checksum>();
            memcpy(conn.upload_hash, in_packet.hash, CHECKSUM_LEN);

            send_sample_resp(cb, tls_buffer, PacketType::RESP_CONTINUE);
        };

    handlers[(int)PacketType::REQ_FILE_TRANSFER_CHUNK]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto& in_packet = *reinterpret_cast<PacketTransferFileChunk*>(cb->buffer);
            auto& conn      = *cb->connection;

            if((conn.fd < 0) || !conn.upload_checksum)
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            size_t length = in_packet.header.total_size - sizeof(PacketHeader);
            if(!write_all(conn.fd, in_packet.file_data, length))
            {
                conn.abort_upload();
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }
            conn.upload_checksum->update(in_packet.file_data, length);

            send_sample_resp(cb, tls_buffer, PacketType::RESP_CONTINUE);
        };

    handlers[(int)PacketType::REQ_FILE_TRANSFER_END]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto& in_packet = *reinterpret_cast<PacketTransferFileEnd*>(cb->buffer);
            auto& conn      = *cb->connection;

            if((conn.fd < 0) || !conn.upload_checksum)
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            size_t length = in_packet.header.total_size - sizeof(PacketHeader);
            if(!write_all(conn.fd, in_packet.file_data, length))
            {
                conn.abort_upload();
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }
            conn.upload_checksum->update(in_packet.file_data, length);

            //Compare the checksum of what we received with the one the client announced
            uint8_t received_hash[CHECKSUM_LEN];
            conn.upload_checksum->finish(received_hash);
            bool matches = (memcmp(received_hash, conn.upload_hash, CHECKSUM_LEN) == 0);

            if(!matches)
            {
                conn.abort_upload(); //Deletes the damaged file
                send_sample_resp(cb, tls_buffer, PacketType::RESP_CRC_FAILED);
                return;
            }

            //Upload finished: keep the file, only forget the upload state
            close(conn.fd);
            conn.fd = -1;
            conn.upload_path.clear();
            conn.upload_checksum.reset();

            send_sample_resp(cb, tls_buffer, PacketType::RESP_FILE_TRANSFER_OK);
        };

    handlers[(int)PacketType::REQ_GET_SETTINGS]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            if(!cb->connection->is_admin)
            {
                send_resp_not_admin(cb, tls_buffer);
                return;
            }
            create_settings_resp_packet(tls_buffer);
            cb->connection->send_response_sync(tls_buffer, sizeof(PacketFileList));
        };

    handlers[(int)PacketType::REQ_SET_SETTING]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            if(!cb->connection->is_admin)
            {
                send_resp_not_admin(cb, tls_buffer);
                return;
            }
            std::lock_guard<std::mutex> guard(g_state.settings_write_lock);
            SetSettingPacket            p = *reinterpret_cast<SetSettingPacket*>(cb->buffer);
            parse_seting_packet_and_set(p);
            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };

    handlers[(int)PacketType::REQ_FILE_LIST]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            create_file_list_packet(cb->connection->current_dir, tls_buffer);
            cb->connection->send_response_sync(tls_buffer, sizeof(PacketFileList));
        };

    handlers[(int)PacketType::REQ_LOGIN]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto&       in_packet = *reinterpret_cast<PacketLogin*>(cb->buffer);
            auto&       conn      = *cb->connection;
            std::string username  = field_to_string(in_packet.username);
            std::string password  = field_to_string(in_packet.password);

            //Logging in again on the same connection first ends the old session
            conn.end_session();

            DatabaseHandler db;
            if(db.login(username, password))
            {
                conn.id          = db.getID(username);
                conn.current_dir = std::string(SERVER_FILES_DIR) + '/' + conn.id;
                mkdir(conn.current_dir.c_str(), 0777);

                if(db.isAdmin(username))
                {
                    if(g_state.b_admin_connected.load())
                    {
                        std::cout << "An admin is already connected!\n";
                        conn.id.clear();
                        conn.current_dir.clear();
                        send_sample_resp(cb, tls_buffer, PacketType::RESP_ADMIN_ALREADY_CONNECTED);
                        return;
                    }
                    std::cout << "An admin connected!\n";
                    g_state.b_admin_connected.exchange(true);
                    conn.is_admin = true;
                }
                create_logged_in_packet(conn.is_admin, tls_buffer);
                conn.send_response_sync(tls_buffer, sizeof(LoggedInPacket));
            }
            else
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_BAD_LOGIN);
                return;
            }
        };

    handlers[(int)PacketType::REQ_COMPRESS] = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            auto&                    in_packet    = *reinterpret_cast<PacketCompress*>(cb->buffer);
            std::string              archive_name = field_to_string(in_packet.archive_name);
            std::string              archive_path = cb->connection->current_dir + '/' + archive_name;
            std::vector<std::string> files_to_compress;

            //The archive name must be one plain name, and the packet may not announce more files than it can hold
            if(!is_valid_filename(archive_name.c_str()) || (in_packet.file_count > MAX_FILES))
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                return;
            }

            if(in_packet.compress_all)
            {
                for(const auto& entry : std::filesystem::recursive_directory_iterator(cb->connection->current_dir + '/'))
                {
                    if(entry.is_regular_file())
                    {
                        files_to_compress.push_back(entry.path().string());
                    }
                }
            }
            else
            {
                for(int i = 0; i < in_packet.file_count; ++i)
                {
                    std::string name = field_to_string(in_packet.file_names[i]);
                    if(!is_valid_filename(name.c_str()))
                    {
                        send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                        return;
                    }
                    std::string file_path = cb->connection->current_dir + '/' + name;
                    if(!does_file_exist(file_path.c_str()))
                    {
                        send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                        return;
                    }
                    files_to_compress.push_back(file_path);
                }
            }

            int  compression_level = get_compression_level(in_packet.compression_level, in_packet.format);
            bool success           = false;

            switch(in_packet.format)
            {
                case Format::ZSTD:
                {
                    success = compress_with_zstd(files_to_compress, archive_path, compression_level);
                    break;
                }
                case Format::GZIP:
                {
                    success = compress_with_gzip(files_to_compress, archive_path, compression_level);
                    break;
                }
                case Format::XZ:
                case Format::LZMA:
                {
                    success = compress_with_xz(files_to_compress, archive_path, compression_level);
                    break;
                }
                case Format::LZ4:
                {
                    success = compress_with_lz4(files_to_compress, archive_path, compression_level);
                    break;
                }
                case Format::ZIP:
                {
                    success = compress_with_zip(files_to_compress, archive_path, compression_level);
                    break;
                }
            }

            if(success)
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_COMPRESS);
            }
            else
            {
                send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
            }
        };

    handlers[(int)PacketType::REQ_CLEAN]
        = [](std::shared_ptr<ConnectionBuffer> cb)
        {
            if(!cb->connection->is_admin)
            {
                send_resp_not_admin(cb, tls_buffer);
                return;
            }
            std::string user_dir = "./tmp/";
            for(const auto& entry : std::filesystem::directory_iterator(user_dir))
            {
                if(entry.is_directory())
                {
                    std::string user_dir_path = entry.path().string();
                    if(!remove_directory(user_dir_path.c_str()))
                    {
                        send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
                        return;
                    }
                }
            }
            send_sample_resp(cb, tls_buffer, PacketType::RESP_OK);
        };
}

void ClientController::process_packet(std::shared_ptr<ConnectionBuffer> cb)
{
    auto packet_type = cb->get_packet_type();

    //Commands that have no handler (unknown numbers, or response types sent by a client) are refused
    if(!handlers[(int)packet_type])
    {
        send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
        return;
    }

    if((packet_type != PacketType::REQ_LOGIN) && (packet_type != PacketType::REQ_PING) && (packet_type != PacketType::REQ_LOGOUT)
        && cb->connection->id.empty())
    {
        send_resp_unauthorized(cb, tls_buffer);
        return;
    }

    //An exception in a worker thread would stop the whole server, so turn it into an error reply
    try
    {
        handlers[(int)packet_type](cb);
    }
    catch(const std::exception& e)
    {
        fprintf(stderr, "Error while handling a request: %s\n", e.what());
        send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
    }
    catch(...)
    {
        fprintf(stderr, "Unknown error while handling a request\n");
        send_sample_resp(cb, tls_buffer, PacketType::RESP_IO_ERROR);
    }
}

thread_local uint8_t
ClientController::tls_buffer[std::numeric_limits<uint16_t>::max()]{};
