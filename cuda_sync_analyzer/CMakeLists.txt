cmake_minimum_required(VERSION 3.14)
project(cuda_sync_analyzer LANGUAGES C CXX CUDA)

find_package(Dyninst REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 11)
endif()

# the RPATH to be used when installing, but only if it's not a system directory
list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
     "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
if("${isSystemDir}" STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
endif()

set(_sources
    src/BPatchBinary.cpp
    src/Common.cpp
    src/DyninstMutatee.cpp
    src/DyninstProcess.cpp
    src/DynOpsClass.cpp
    src/FindCudaSync.cpp
    src/InstrSyncOffset.cpp
    src/LaunchIdentifySync.cpp
    src/LocateCudaSynchronization.cpp
    src/SerializeTypes.cpp)

set(_private_headers
    src/BPatchBinary.h
    src/Common.h
    src/DyninstMutatee.h
    src/DyninstProcess.h
    src/DynOpsClass.h
    src/InstrSyncOffset.h
    src/LaunchIdentifySync.h
    src/LocateCudaSynchronization.h
    src/LogInfo.h
    src/SerializeTypes.h)

set(_public_headers src/FindCudaSync.h)

configure_file("${PROJECT_SOURCE_DIR}/src/Constants.h.in"
               "${PROJECT_SOURCE_DIR}/src/Constants.h")

add_library(cuda_sync_analyzer SHARED ${_sources} ${_private_headers}
                                      ${_public_headers})

set_target_properties(cuda_sync_analyzer PROPERTIES PUBLIC_HEADER
                                                    ${_public_headers})

target_link_libraries(cuda_sync_analyzer PUBLIC Dyninst::dyninstAPI
                                                OpenSSL::Crypto)

install(
  TARGETS cuda_sync_analyzer
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib/static
  RUNTIME DESTINATION bin
  PUBLIC_HEADER DESTINATION include)

install(FILES src/SyncDriverVerisons.txt DESTINATION lib)

add_subdirectory(src/FindSyncHelper)
add_subdirectory(src/InsertTimingInstr)
add_subdirectory(src/artifacts)

add_executable(mutateLibcuda src/main.cpp)
link_directories(${CMAKE_BINARY_DIR}/src)
target_link_libraries(mutateLibcuda LINK_PUBLIC "cuda_sync_analyzer")
target_compile_options(mutateLibcuda PUBLIC -O3)
install(TARGETS mutateLibcuda RUNTIME DESTINATION bin)
