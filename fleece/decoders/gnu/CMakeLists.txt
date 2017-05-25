IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    SET(GNU_DIR "" CACHE STRING "Base directory for gnu binutils" FORCE)
ENDIF()

IF(NOT GNU_DIR STREQUAL "")
    
    MESSAGE(STATUS "Using decoder: gnu")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_DECODER_SOURCE ${FLEECE_DECODER_SOURCE} gnu/gnu_aarch64.C
    gnu/gnu_x86.C gnu/gnu_ppc.C PARENT_SCOPE) 

    SET(FLEECE_DECODER_LIBRARIES ${FLEECE_DECODER_LIBRARIES} opcodes PARENT_SCOPE)
    
    SET(DECODER_INSTALL_DIRS ${DECODER_INSTALL_DIRS} ${GNU_DIR} PARENT_SCOPE)

ENDIF()
