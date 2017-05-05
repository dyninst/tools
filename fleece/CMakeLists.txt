cmake_minimum_required (VERSION 2.6.4)

project (Fleece)

IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Default installation path" FORCE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)

    set(DYNINST_DIR "/usr" CACHE STRING "Base directory for Dyninst" FORCE)
    set(XED_DIR "/usr" CACHE STRING "Base directory for XED" FORCE)
    set(GNU_DIR "/usr" CACHE STRING "Base directory for Binutils" FORCE)
    set(LLVM_DIR "/usr" CACHE STRING "Base directory for LLVM" FORCE)
    set(CAPSTONE_DIR "/usr" CACHE STRING "Base directory for capstone" FORCE)

ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)

set (DYNINST_LIBDIR "${DYNINST_DIR}/lib")
set (DYNINST_INCLUDEDIR "${DYNINST_DIR}/include")

set (XED_LIBDIR "${XED_DIR}/lib")
set (XED_INCLUDEDIR "${XED_DIR}/include")

set (GNU_LIBDIR "${GNU_DIR}/lib")
set (GNU_INCLUDEDIR "${GNU_DIR}/include")

set (LLVM_LIBDIR "${LLVM_DIR}/lib")
set (LLVM_INCLUDEDIR "${LLVM_DIR}/include")

set (CAPSTONE_LIBDIR "${CAPSTONE_DIR}/lib")
set (CAPSTONE_INCLUDEDIR "${CAPSTONE_DIR}/include")

set (DEPS_LIBDIR ${DYNINST_LIBDIR} ${XED_LIBDIR} ${GNU_LIBDIR} ${LLVM_LIBDIR} ${CAPSTONE_LIBDIR})
set (DEPS_INCLUDEDIR ${DYNINST_INCLUDEDIR} ${XED_INCLUDEDIR} ${GNU_INCLUDEDIR} ${LLVM_INCLUDEDIR} ${CAPSTONE_INCLUDEDIR})

# Which custom libraries should be linked against fleece?
set (FLEECE_LIBRARIES fleeceutil fleecedecoders fleecereporting)
set (OTHER_LIBRARIES z instructionAPI xed LLVM opcodes capstone rt bfd iberty dl elf)
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
