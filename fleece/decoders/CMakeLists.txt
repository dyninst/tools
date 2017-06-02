
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

# When binaries link against this library, which headers should be included?
include_directories ("${PROJECT_SOURCE_DIR}/h" ${DEPS_INCLUDEDIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# Build these sources as libfleecedecoders (.so on Linux or .dll on Windows)
add_library(fleecedecoders SHARED ${FLEECE_DECODER_SOURCE})
