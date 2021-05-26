cmake_minimum_required(VERSION 3.0)
project(net2disk CXX)

add_subdirectory(libixxx)
add_subdirectory(libixxxutil)


set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)


add_executable(net2disk
    net2disk.cc
    pcap.cc
    aio_device.cc
    )
set_property(TARGET net2disk PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/libixxx
    ${CMAKE_SOURCE_DIR}/libixxxutil
    )
target_link_libraries(net2disk
    ixxxutil_static
    ixxx_static
    Threads::Threads
    )



add_executable(test_aio
    test_aio.cc
    aio_device.cc
    )
set_property(TARGET test_aio PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/libixxx
    ${CMAKE_SOURCE_DIR}/libixxxutil
    )
target_link_libraries(test_aio
    ixxxutil_static
    ixxx_static
    Threads::Threads
    )

add_executable(dev2pcap
    dev2pcap.cc
    pcap.cc
    )
set_property(TARGET dev2pcap PROPERTY INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/libixxx
    ${CMAKE_SOURCE_DIR}/libixxxutil
    )
target_link_libraries(dev2pcap
    ixxxutil_static
    ixxx_static
    )

