project(NetScanApp LANGUAGES CXX)


SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -frtti")

set(Sources__Packet
    "src/ns_ArpManager.cpp"
    "src/ns_DnsManager.cpp"
    "src/ns_NetScan.cpp"
)

set(Sources
    "src/main.cpp"
)

set(Sources__StateMachine
    "src/ns_SM.cpp"

)
source_group("NetScanApp/src/Packet" FILES ${Sources__Packet})
source_group("NetScanApp/src/State-Machine" FILES ${Sources__StateMachine})
source_group("NetScanApp/src" FILES ${Sources})

set(Headers__Packet
    "inc/ns_ArpManager.h"
     "inc/ns_Common.h"
     "inc/ns_DnsManager.h"
     "inc/ns_NetScan.h"

)
set(Headers__StateMachine
    "inc/ns_SM_common.h"
    "inc/ns_SM.h"
     "inc/ns_SM_States.h"
     "inc/ns_SM_utils.h"
)
set(Headers
    "inc/main.h"
)
source_group("NetScanApp/inc/Packet" FILES ${Headers__Packet})
source_group("NetScanApp/inc/State-Machine" FILES ${Headers__StateMachine})

source_group("NetScanApp/inc" FILES ${Headers})

########All Files#############
set(ALL_FILES

     ${Sources}
     ${Sources__Packet}
     ${Sources__StateMachine}
     ${Headers}
     ${Headers__Packet}
      ${Headers__StateMachine}

 )

INCLUDE( ${CMAKE_SOURCE_DIR}/cmake-module/CodeCoverage.cmake )

  append_coverage_compiler_flags()
if(DEFINED UNIT_TEST)
add_library(${PROJECT_NAME} STATIC  ${ALL_FILES} )
else()
add_executable(${PROJECT_NAME} ${ALL_FILES})
endif()


target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc")
target_include_directories(${PROJECT_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../external/tinyfsm/include")
#Output Directory

set_target_properties(${PROJECT_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
