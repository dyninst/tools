cmake_minimum_required (VERSION 3.1)

set(default_build_type "Debug")
set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
      STRING "Choose the type of build." FORCE)
SET(CMAKE_CXX_STANDARD 11)

project(cuda_sync_analyzer LANGUAGES C CXX CUDA)

# the RPATH to be used when installing, but only if it's not a system directory
LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")

find_package(CUDA REQUIRED)

## Get dyninst library info
include(${CMAKE_SOURCE_DIR}/DyninstInstall.cmake)
# setup cuda
#include(${CMAKE_SOURCE_DIR}/CudaLibDetect.cmake)

add_subdirectory(src)

