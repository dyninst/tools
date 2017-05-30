
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

SET(FLEECE_ARCH_SOURCE Architecture.C)
SET(FLEECE_ARCH_DIRS )

SET(IGNORED_DIRS CMakeFiles)

SUBDIRLIST(SUBDIRS ${CMAKE_CURRENT_SOURCE_DIR})
FOREACH(subdir ${SUBDIRS})
    SET(IGNORED FALSE)
    FOREACH(ignored_dir ${IGNORED_DIRS})
        IF(${subdir} STREQUAL ${ignored_dir})
            MESSAGE(STATUS "Ignored arch directory: " ${ignored_dir})
            SET(IGNORED TRUE)
        ENDIF()
    ENDFOREACH()

    IF(NOT IGNORED)
        MESSAGE(STATUS "Added arch directory: " ${subdir})
        ADD_SUBDIRECTORY(${subdir})
        SET(FLEECE_ARCH_DIRS ${FLEECE_ARCH_DIRS} ${subdir})
    ENDIF()
ENDFOREACH()

# When binaries link against this library, which headers should be included?
include_directories ("${PROJECT_SOURCE_DIR}/h" ${DEPS_INCLUDEDIR} ${FLEECE_ARCH_DIRS})

# Build these sources as libfleeceutil (.so on Linux or .dll on Windows)
add_library(fleecearch SHARED ${FLEECE_ARCH_SOURCE})

