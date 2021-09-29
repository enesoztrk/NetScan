cmake_minimum_required(VERSION 3.5)

project(NetScan LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(PkgConfig REQUIRED)
pkg_search_module(GTEST  REQUIRED gtest)
pkg_search_module(GMOCK  REQUIRED gmock)

include_directories(${GTEST_INCLUDE_DIRS})
link_directories(${GTEST_LIBRARY_DIRS})
link_libraries(${GTEST_LIBRARIES})

include_directories(${GMOCK_INCLUDE_DIRS})
link_directories(${GMOCK_LIBRARY_DIRS})
link_libraries(${GMOCK_LIBRARIES})

message(STATUS "GTEST_LIBRARIES: ${GTEST_LIBRARIES} in ${GTEST_LIBRARY_DIRS}")
message(STATUS "GMOCK_LIBRARIES: ${GMOCK_LIBRARIES} in ${GMOCK_LIBRARIES}")

find_package(PkgConfig REQUIRED)
pkg_search_module(PCAP REQUIRED PcapPlusPlus)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
link_libraries(${PCAP_LIBRARIES})

message(STATUS "PCAP_LIBRARIES: ${PCAP_LIBRARIES} in ${PCAP_LIBRARY_DIRS}")
add_subdirectory(NetScanApp/)
add_subdirectory(NetScanApp-UnitTest/)
