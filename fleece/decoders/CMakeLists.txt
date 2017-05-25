
MACRO(SUBDIRLIST result curdir)
    FILE(GLOB children RELATIVE ${curdir} ${curdir}/*)
    SET(dirlist "")
    FOREACH(child ${children})
        IF(IS_DIRECTORY ${curdir}/${child})
            LIST(APPEND dirlist ${child})
        ENDIF()
    ENDFOREACH()
    SET(${result} ${dirlist})
ENDMACRO()

SET(FLEECE_DECODER_SOURCE Decoder.C Normalization.C)
SET(FLEECE_DECODER_LIBRARIES )

SET(IGNORED_DIRS CMakeFiles)

SUBDIRLIST(SUBDIRS ${CMAKE_CURRENT_SOURCE_DIR})
FOREACH(subdir ${SUBDIRS})
    SET(IGNORED FALSE)
    FOREACH(ignored_dir ${IGNORED_DIRS})
        IF(${subdir} STREQUAL ${ignored_dir})
            MESSAGE(STATUS "Ignored decoder directory: " ${ignored_dir})
            SET(IGNORED TRUE)
        ENDIF()
    ENDFOREACH()

    IF(NOT IGNORED)
        MESSAGE(STATUS "Added decoder directory: " ${subdir})
        ADD_SUBDIRECTORY(${subdir})
    ENDIF()
ENDFOREACH()

SET(FLEECE_DECODER_LIBRARIES ${FLEECE_DECODER_LIBRARIES} PARENT_SCOPE)
SET(DECODER_INSTALL_DIRS ${DECODER_INSTALL_DIRS} PARENT_SCOPE)
SET(DEPS_INCLUDEDIR )

FOREACH(dec_install_dir ${DECODER_INSTALL_DIRS})
    SET (DEPS_INCLUDEDIR ${DEPS_INCLUDEDIR} "${dec_install_dir}/include")
ENDFOREACH()

# Set the sources that should be compiled into the library
#set (FLEECE_DECODERS_SOURCE Decoder.C dyninst_aarch64.C dyninst_x86_64.C dyninst_x86_32.C dyninst_armv6.C gnu_aarch64.C
#gnu_x86.C gnu_ppc.C gnu_ppc_32.C Normalization.C null_decoders.C xed_x86.C capstone_aarch64.C
#capstone_x86_32.C capstone_x86_64.C capstone_ppc.C dyninst_ppc.C dyninst_ppc_32.C) 

#IF(USE_LLVM)
#    set (FLEECE_DECODERS_SOURCE ${FLEECE_DECODERS_SOURCE} llvm_common.C llvm_aarch64.C llvm_x86_64.C llvm_x86_32.C llvm_armv6.C llvm_ppc.C
#    llvm_ppc_32.C)
#ENDIF(USE_LLVM)

#set(ALL_LIBRARIES ${ALL_LIBRARIES} not_a_library PARENT_SCOPE)
#MESSAGE(STATUS "ALL_LIBRARIES is: " ${ALL_LIBRARIES})

MESSAGE(STATUS "DEPS_INCLUDEDIR is " ${DEPS_INCLUDEDIR})

# When binaries link against this library, which headers should be included?
include_directories ("${PROJECT_SOURCE_DIR}/h" ${DEPS_INCLUDEDIR})

# Build these sources as libfleecedecoders (.so on Linux or .dll on Windows)
add_library(fleecedecoders SHARED ${FLEECE_DECODER_SOURCE})
