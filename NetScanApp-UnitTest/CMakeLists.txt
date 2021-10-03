project(NetScanApp-UnitTest LANGUAGES CXX)

#SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-elide-constructors")


add_executable(${PROJECT_NAME} src/main.cpp inc/MockDnsManager.h inc/MockArpManager.h src/TEST_ArpManager.cpp inc/MockPacket.h)

target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../NetScanApp/inc")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(${PROJECT_NAME} PUBLIC NetScanApp)
#Output Directory

set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
