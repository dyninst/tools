    
IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    SET(CAPSTONE_DIR "" CACHE STRING "Base directory for capstone" FORCE)
ENDIF()

IF(NOT CAPSTONE_DIR STREQUAL "")

    MESSAGE(STATUS "Using decoder: capstone")

    # Set the sources that should be compiled into the library
    SET(FLEECE_DECODER_SOURCE ${FLEECE_DECODER_SOURCE} capstone/capstone_aarch64.C
    capstone/capstone_x86.C capstone/capstone_ppc.C PARENT_SCOPE) 

    SET(FLEECE_DECODER_LIBRARIES ${FLEECE_DECODER_LIBRARIES} capstone PARENT_SCOPE)

    SET(DECODER_INSTALL_DIRS ${DECODER_INSTALL_DIRS} ${CAPSTONE_DIR} PARENT_SCOPE)

ENDIF()
