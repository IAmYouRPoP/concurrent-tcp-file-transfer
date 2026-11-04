cmake_minimum_required(VERSION 3.10)
project(PCD LANGUAGES CXX)

# ---------- Global settings ----------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Put the finished programs (server and client) directly inside build/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Optional: cmake -DSANITIZE=ON .. builds with AddressSanitizer + UndefinedBehaviorSanitizer
# (they find memory errors, leaks and undefined behaviour while the program runs)
option(SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------- Libraries the project needs ----------
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)    # password hashing and file checksums

# SQLite (user database):
#  - if you put sqlite3.c and sqlite3.h into src/libs, they are compiled together with the project
#  - otherwise the SQLite installed on the computer is used (sudo apt install libsqlite3-dev)
if(EXISTS ${CMAKE_SOURCE_DIR}/src/libs/sqlite3.c)
    enable_language(C)
    add_library(sqlite3_local STATIC src/libs/sqlite3.c)
    target_include_directories(sqlite3_local PUBLIC ${CMAKE_SOURCE_DIR}/src/libs)
    target_link_libraries(sqlite3_local PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
    set(SQLITE_TARGET sqlite3_local)
else()
    find_package(SQLite3 REQUIRED)
    set(SQLITE_TARGET SQLite::SQLite3)
endif()

# Folders that hold shared header files (so #include "packets.hpp" works)
include_directories(src/common src/db)

# ---------- Server ----------
add_executable(server
    src/server/main.cpp
    src/server/connection.cpp
    src/server/client_controller.cpp
)
target_link_libraries(server PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE_TARGET}
    zstd lz4 lzma z zip archive    # compression libraries
)

# ---------- Client ----------
add_executable(client src/client/main.cpp)
target_link_libraries(client PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)
