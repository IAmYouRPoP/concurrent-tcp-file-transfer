#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <unistd.h>

//Writes all the bytes (write() can write less than asked). Returns false on error.
inline bool write_all(int fd, const uint8_t* data, size_t length)
{
    size_t done = 0;
    while(done < length)
    {
        ssize_t n = write(fd, data + done, length - done);
        if(n < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            return false;
        }
        done += static_cast<size_t>(n);
    }
    return true;
}
