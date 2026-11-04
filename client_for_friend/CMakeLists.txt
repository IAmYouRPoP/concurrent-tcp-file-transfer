cmake_minimum_required(VERSION 3.10)
project(PCD_Client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(src/common)

add_executable(client src/client/main.cpp)
target_link_libraries(client PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)
