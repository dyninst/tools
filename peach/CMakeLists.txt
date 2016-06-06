cmake_minimum_required (VERSION 2.6.4)

project (Peach)

set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Default installation path" FORCE)
set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)

option(BUILD_SHARED "Build and link shared libraries?" ON)
option(BUILD_STATIC "Build and link static libraries?" OFF)


# Which custom libraries should be linked against peach?
set (PEACH_LIBRARIES peachutil peachdecoders peachreporting)
set (OTHER_LIBRARIES z instructionAPI xed LLVM opcodes rt bfd iberty dl)
set (ALL_LIBRARIES ${PEACH_LIBRARIES} ${OTHER_LIBRARIES})

set (CMAKE_CXX_FLAGS "-std=c++11 ")
set (CMAKE_C_FLAGS "")

include_directories(${PROJECT_BINARY_DIR}/h)

add_subdirectory(decoders)
add_subdirectory(reporting)
add_subdirectory(util)

add_executable(peach peach.C)
target_link_libraries(peach LINK_PUBLIC ${ALL_LIBRARIES})
target_include_directories(peach PUBLIC "h")
