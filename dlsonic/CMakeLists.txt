cmake_minimum_required(VERSION 3.13.0)
project(dlsonicproject LANGUAGES CXX)

set(_dyninst_dir $ENV{Dyninst_DIR})
set(Dyninst_DIR ${_dyninst_dir})
unset(_dyninst_dir)

# Use the Dyninst-provided CMake modules
set(CMAKE_MODULE_PATH
    "${Dyninst_DIR}"
    "${Dyninst_DIR}/Modules"
    ${CMAKE_MODULE_PATH})

# Import the Dyninst components
find_package(Dyninst REQUIRED
             COMPONENTS common
                        dyninstAPI
                        instructionAPI
                        parseAPI
                        symtabAPI
                        common)

# Read the cache generated from building Dyninst
load_cache(${Dyninst_DIR}
           READ_WITH_PREFIX DYNINST_
           Boost_LIBRARIES
           Boost_INCLUDE_DIRS
           Boost_LIBRARY_DIRS
           Boost_DEFINES
           TBB_INCLUDE_DIRS)

# The main tool executable
add_executable(dlsonic dlsonic.C)
target_include_directories(dlsonic PRIVATE ${DYNINST_INCLUDE_DIR} ${DYNINST_Boost_INCLUDE_DIRS} ${DYNINST_TBB_INCLUDE_DIRS})
target_link_libraries(dlsonic dyninstAPI ${DYNINST_Boost_LIBRARIES})

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	target_compile_options(dlsonic PRIVATE "-fno-pie")
	target_link_options(dlsonic PRIVATE "-no-pie")
endif()

add_custom_target(dlsonicproject DEPENDS dlsonic)

add_subdirectory(testbins)
