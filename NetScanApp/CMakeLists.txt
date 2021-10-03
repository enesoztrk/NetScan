project(NetScanApp LANGUAGES CXX)


#SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-elide-constructors")


add_library(${PROJECT_NAME} STATIC src/main.cpp inc/main.h inc/ns_ArpManager.h src/ns_ArpManager.cpp inc/ns_Common.h)
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc")
#Output Directory

set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
