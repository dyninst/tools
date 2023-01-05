cmake_minimum_required(VERSION 3.13.0)
project(testbinaries LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_library(hello SHARED hello_lib_header.H hello_lib_impl.C)
set_target_properties(hello PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(hello PROPERTIES LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libhello.ver")
add_executable(trydl trydl.C)
target_link_libraries(trydl hello dl)
target_compile_options(hello PRIVATE -fPIC)
target_compile_options(trydl PRIVATE -fPIC)
