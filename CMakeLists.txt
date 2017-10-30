cmake_minimum_required(VERSION 3.8)
project(DHellman2)

set(CMAKE_C_STANDARD 11)
include_directories(/usr/local/opt/gmp/include)
link_directories(/usr/local/opt/gmp/lib)
link_libraries(gmp)
include_directories(/usr/local/opt/openssl/include)
link_directories(/usr/local/opt/openssl/lib)
link_libraries(crypto)

set(SOURCE_FILES main.c)
add_executable(DHellman2 ${SOURCE_FILES})