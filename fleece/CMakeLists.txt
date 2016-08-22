cmake_minimum_required (VERSION 2.6.4)

project (Fleece)

IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Default installation path" FORCE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)


    set(DYNINST_LIBDIR "/usr/lib" CACHE STRING "Library directory for Dyninst" FORCE)
    set(DYNINST_INCLUDEDIR "/usr/include" CACHE STRING "Include directory for Dyninst" FORCE)
    
    set(XED_LIBDIR "/usr/lib" CACHE STRING "Library directory for XED" FORCE)
    set(XED_INCLUDEDIR "/usr/include" CACHE STRING "Include directory for XED" FORCE)

    set(GNU_LIBDIR "/usr/lib" CACHE STRING "Library directory for binutils" FORCE)
    set(GNU_INCLUDEDIR "/usr/include" CACHE STRING "Include directory for binutils" FORCE)

    set(LLVM_LIBDIR "/usr/lib" CACHE STRING "Library directory for LLVM" FORCE)
    set(LLVM_INCLUDEDIR "/usr/include" CACHE STRING "Include directory for LLVM" FORCE)

ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

option(BUILD_SHARED "Build and link shared libraries?" ON)
option(BUILD_STATIC "Build and link static libraries?" OFF)

set (DEPS_LIBDIR ${DYNINST_LIBDIR} ${XED_LIBDIR} ${GNU_LIBDIR} ${LLVM_LIBDIR})
set (DEPS_INCLUDEDIR ${DYNINST_INCLUDEDIR} ${XED_INCLUDEDIR} ${GNU_INCLUDEDIR} ${LLVM_INCLUDEDIR})

# Which custom libraries should be linked against fleece?
set (FLEECE_LIBRARIES fleeceutil fleecedecoders fleecereporting)
set (OTHER_LIBRARIES z instructionAPI xed LLVM opcodes rt bfd iberty dl)
set (ALL_LIBRARIES ${FLEECE_LIBRARIES} ${OTHER_LIBRARIES})

set (CMAKE_CXX_FLAGS "-std=c++0x")
set (CMAKE_C_FLAGS "")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -gdwarf-2 -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")

include_directories(${PROJECT_BINARY_DIR}/h ${DEPS_INCLUDEDIR})
link_directories(${DEPS_LIBDIR})

add_subdirectory(decoders)
add_subdirectory(reporting)
add_subdirectory(util)

add_executable(fleece fleece.C)
target_link_libraries(fleece LINK_PUBLIC ${ALL_LIBRARIES})
target_include_directories(fleece PUBLIC "h")
