cmake_minimum_required(VERSION 3.14.0 FATAL_ERROR)
project(noreturn LANGUAGES CXX)

find_package(Dyninst REQUIRED)

add_executable(noreturn_check noreturn_check.cpp)
target_link_libraries(noreturn_check PRIVATE Dyninst::dyninstAPI Dyninst::parseAPI)

add_executable(noreturn_scan noreturn_scan.cpp)
target_link_libraries(noreturn_scan PRIVATE Dyninst::parseAPI Dyninst::symtabAPI Dyninst::instructionAPI)

foreach(_tool noreturn_check noreturn_scan)
  target_compile_options(${_tool} PRIVATE -Wall -Wextra)
endforeach()

install(TARGETS noreturn_check noreturn_scan RUNTIME DESTINATION bin)
install(PROGRAMS generate_noreturn_list.sh DESTINATION bin)
