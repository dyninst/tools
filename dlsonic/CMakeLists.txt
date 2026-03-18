cmake_minimum_required(VERSION 3.13.0)
project(dlsonicproject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

find_package(Dyninst REQUIRED)

add_executable(dlsonic dlsonic.C)
target_link_libraries(dlsonic PUBLIC Dyninst::dyninstAPI)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	target_compile_options(dlsonic PRIVATE "-fno-pie")
	target_link_options(dlsonic PRIVATE "-no-pie")
endif()

add_custom_target(dlsonicproject DEPENDS dlsonic)

add_subdirectory(testbins)
