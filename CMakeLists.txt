cmake_minimum_required(VERSION 3.15)
project(no_block_DNS)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -levent")
set(INC_DIR /usr/lib/libevent/build/include/
        /usr/lib/libevent/include/)
set(LINK_DIR /lib/libevent/build/lib)

include_directories(${INC_DIR})
link_directories(${LINK_DIR})

add_executable(no_block_DNS
        main.cpp)
target_link_libraries(no_block_DNS
        /lib/libevent/build/lib/libevent-2.2.so.1.0.0
        /lib/libevent/build/lib/libevent_core-2.2.so.1.0.0
        /lib/libevent/build/lib/libevent_extra-2.2.so.1.0.0
        /lib/libevent/build/lib/libevent_mbedtls-2.2.so.1.0.0
        /lib/libevent/build/lib/libevent_openssl-2.2.so.1.0.0
        /lib/libevent/build/lib/libevent_pthreads-2.2.so.1.0.0
        )