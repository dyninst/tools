cmake_minimum_required (VERSION 2.6.4)

project (Fleece)

IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Default installation path" FORCE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

set(FLEECE_DECODER_LIBRARIES )
add_subdirectory(decoders)

SET(DEPS_LIBDIR )

FOREACH(dec_install_dir ${DECODER_INSTALL_DIRS})
    SET (DEPS_LIBDIR ${DEPS_LIBDIR} "${dec_install_dir}/lib")
ENDFOREACH()

# Which custom libraries should be linked against fleece?
set (FLEECE_LIBRARIES fleeceutil fleecedecoders fleecereporting fleecearch)
set (OTHER_LIBRARIES z rt bfd iberty dl elf)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -gdwarf-2 -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

include_directories(${PROJECT_BINARY_DIR}/h)
link_directories(${DEPS_LIBDIR})

add_subdirectory(reporting)
add_subdirectory(arch)
add_subdirectory(util)

set (ALL_LIBRARIES ${FLEECE_LIBRARIES} ${FLEECE_DECODER_LIBRARIES} ${OTHER_LIBRARIES})

add_executable(fleece fleece.C)
target_link_libraries(fleece LINK_PUBLIC ${ALL_LIBRARIES})
target_include_directories(fleece PUBLIC "${PROJECT_SOURCE_DIR}/h")
