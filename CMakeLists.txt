cmake_minimum_required(VERSION 3.5)
project(semantics_broad_test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp src/Scanner.h)
add_executable(semantics_broad_test ${SOURCE_FILES})