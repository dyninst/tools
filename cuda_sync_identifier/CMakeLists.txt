cmake_minimum_required (VERSION 3.1)

set(default_build_type "Debug")
set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
      STRING "Choose the type of build." FORCE)
SET(CMAKE_CXX_STANDARD 11)

project(cuda_sync_identifier)

find_package(CUDA REQUIRED)

## Get dyninst library info
include(${CMAKE_SOURCE_DIR}/DyninstInstall.cmake)
# setup cuda
#include(${CMAKE_SOURCE_DIR}/CudaLibDetect.cmake)

add_subdirectory(src)
add_subdirectory(test)
