project(NetScanApp LANGUAGES CXX)




add_executable(${PROJECT_NAME} src/main.cpp inc/main.h inc/ns_ArpManager.h inc/ns_NetScan.h inc/ns_DnsManager.h)
