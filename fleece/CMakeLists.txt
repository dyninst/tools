cmake_minimum_required (VERSION 2.6.4)

project (Fleece)

set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Default installation path" FORCE)
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)

option(BUILD_SHARED "Build and link shared libraries?" ON)
option(BUILD_STATIC "Build and link static libraries?" OFF)


# Which custom libraries should be linked against fleece?
set (FLEECE_LIBRARIES fleeceutil fleecedecoders fleecereporting)
set (OTHER_LIBRARIES z instructionAPI xed LLVM opcodes rt bfd iberty dl)
set (ALL_LIBRARIES ${FLEECE_LIBRARIES} ${OTHER_LIBRARIES})

set (CMAKE_CXX_FLAGS "-std=c++0x")
set (CMAKE_C_FLAGS "")


include_directories(${PROJECT_BINARY_DIR}/h)

add_subdirectory(decoders)
add_subdirectory(reporting)
add_subdirectory(util)

add_executable(fleece fleece.C)
target_link_libraries(fleece LINK_PUBLIC ${ALL_LIBRARIES})
target_include_directories(fleece PUBLIC "h")
