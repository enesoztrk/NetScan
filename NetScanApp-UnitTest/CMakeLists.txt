project(NetScanApp-UnitTest LANGUAGES CXX)

SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -frtti")
find_package(PkgConfig REQUIRED)
pkg_search_module(GTEST  REQUIRED gtest)
pkg_search_module(GMOCK  REQUIRED gmock)
INCLUDE( ${CMAKE_SOURCE_DIR}/cmake-module/CodeCoverage.cmake )

  append_coverage_compiler_flags()
include_directories(${GTEST_INCLUDE_DIRS})
link_directories(${GTEST_LIBRARY_DIRS})
link_libraries(${GTEST_LIBRARIES})

include_directories(${GMOCK_INCLUDE_DIRS})
link_directories(${GMOCK_LIBRARY_DIRS})
link_libraries(${GMOCK_LIBRARIES})

message(STATUS "GTEST_LIBRARIES: ${GTEST_LIBRARIES} in ${GTEST_LIBRARY_DIRS}")
message(STATUS "GMOCK_LIBRARIES: ${GMOCK_LIBRARIES} in ${GMOCK_LIBRARIES}")


add_executable(${PROJECT_NAME} src/main.cpp inc/MockDnsManager.h inc/MockArpManager.h
    src/TEST_ArpManager.cpp  src/TEST_DnsManager.cpp src/TEST_NetScan.cpp inc/MockPacket.h)

target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../NetScanApp/inc")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(${PROJECT_NAME} PUBLIC NetScanApp)
#Output Directory

set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
