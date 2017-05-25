IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    SET(DYNINST_DIR "" CACHE STRING "Base directory for dyninst" FORCE)
ENDIF()

IF(NOT DYNINST_DIR STREQUAL "")

    MESSAGE(STATUS "Using decoder: dyninst")

    # Set the sources that should be compiled into the library
    SET(FLEECE_DECODER_SOURCE ${FLEECE_DECODER_SOURCE} dyninst/dyninst_aarch64.C
    dyninst/dyninst_x86_32.C dyninst/dyninst_x86_64.C dyninst/dyninst_ppc.C PARENT_SCOPE) 

    SET(FLEECE_DECODER_LIBRARIES ${FLEECE_DECODER_LIBRARIES} instructionAPI PARENT_SCOPE)

    SET(DECODER_INSTALL_DIRS ${DECODER_INSTALL_DIRS} ${DYNINST_DIR} PARENT_SCOPE)

ENDIF()
