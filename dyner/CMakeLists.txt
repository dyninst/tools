cmake_minimum_required(VERSION 3.13.0 FATAL_ERROR)
project(dyner)

find_package(Dyninst REQUIRED)
find_package(TCL REQUIRED)

add_executable(dyner src/dyner.C src/breakpoint.h src/dynerList.h)
target_compile_options(dyner PRIVATE -Wall -Wextra)
target_include_directories(dyner PRIVATE ${TCL_INCLUDE_PATH} ${DYNINST_INCLUDE_DIR})
target_link_libraries(dyner PRIVATE dyninstAPI dynC_API ${TCL_LIBRARY})
