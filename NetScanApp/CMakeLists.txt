project(NetScanApp LANGUAGES CXX)


SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -frtti")

set(Sources__Packet
    "src/ns_ArpManager.cpp"
)

set(Sources
    "src/main.cpp"
)
source_group("NetScanApp/src/Packet" FILES ${Sources__Packet})
source_group("NetScanApp/src" FILES ${Sources})

set(Headers__Packet
    "inc/ns_ArpManager.h"
     "inc/ns_Common.h"
     "inc/ns_DnsManager.h"
)

set(Headers
    "inc/main.h"
)
source_group("NetScanApp/inc/Packet" FILES ${Headers__Packet})
source_group("NetScanApp/inc" FILES ${Headers})

########All Files#############
set(ALL_FILES

     ${Sources}
     ${Sources__Packet}
     ${Headers}
     ${Headers__Packet}

 )


if(DEFINED UNIT_TEST)
add_library(${PROJECT_NAME} STATIC  ${ALL_FILES} )
else()
add_executable(${PROJECT_NAME} ${ALL_FILES})
endif()


target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc")
#Output Directory

set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
