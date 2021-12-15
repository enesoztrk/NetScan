cmake_minimum_required(VERSION 3.5)

project(NetScan_Prj LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



find_package(PkgConfig REQUIRED)
pkg_search_module(PCAP REQUIRED PcapPlusPlus)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
link_libraries(${PCAP_LIBRARIES})

message(STATUS "PCAP_LIBRARIES: ${PCAP_LIBRARIES} in ${PCAP_LIBRARY_DIRS}")

if(DEFINED MOCK_SUPPORT)
    add_definitions("-DMOCK_SUPPORT")
endif()


if(DEFINED UNIT_TEST)
add_definitions(-DUNIT_TEST)
add_subdirectory(NetScanApp-UnitTest/)
endif()

add_subdirectory(NetScanApp/)


