project(NetScanApp-UnitTest LANGUAGES CXX)



add_executable(${PROJECT_NAME} src/main.cpp inc/MockDnsManager.h inc/MockArpManager.h)

target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../NetScanApp/inc")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
