#pragma once

// Small helper used to check that a file arrived without damage.
// It uses MD5 from OpenSSL, which is only used here to detect transfer
// errors (not for security). The result is always 16 bytes.

#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <openssl/evp.h>
#include <unistd.h>

constexpr size_t CHECKSUM_LEN = 16;

class Checksum
{
public:
    Checksum() : ctx_(EVP_MD_CTX_new())
    {
        EVP_DigestInit_ex(ctx_, EVP_md5(), nullptr);
    }

    ~Checksum()
    {
        EVP_MD_CTX_free(ctx_);
    }

    Checksum(const Checksum&)            = delete;
    Checksum& operator=(const Checksum&) = delete;

    //Feed more bytes of the file
    void update(const uint8_t* data, size_t length)
    {
        EVP_DigestUpdate(ctx_, data, length);
    }

    //Get the final 16 byte result (call only once)
    void finish(uint8_t out[CHECKSUM_LEN])
    {
        unsigned int length = 0;
        EVP_DigestFinal_ex(ctx_, out, &length);
    }

private:
    EVP_MD_CTX* ctx_;
};

//Reads a whole file from disk and gives its checksum. Returns false if the file cannot be read.
inline bool checksum_of_file(const char* path, uint8_t out[CHECKSUM_LEN])
{
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        return false;
    }

    Checksum checksum;
    uint8_t  block[65536];
    ssize_t  count;
    while((count = read(fd, block, sizeof(block))) > 0)
    {
        checksum.update(block, static_cast<size_t>(count));
    }
    close(fd);

    if(count < 0)
    {
        return false;
    }
    checksum.finish(out);
    return true;
}
