cmake_minimum_required(VERSION 2.8)

project(tcpsesscount)
include(FindPCAP.cmake)

set(SOURCE_FILES main.cpp)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARY})
