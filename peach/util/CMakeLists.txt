# Set the sources that should be compiled into the library
set (PEACH_UTIL_SOURCE Alias.C Architecture.C Bitfield.C BitTypeMap.C BitTypes.C Hashcounter.C Info.C MappedInst.C MapTable.C Mask.C Mystring.C Options.C RegisterSet.C)

# When binaries link against this library, which headers should be included?
include_directories (${PROJECT_SOURCE_DIR}/h})

if(BUILD_SHARED)
    # Build these sources as libpeachutil (.so on Linux or .dll on Windows)
    add_library(peachutil SHARED ${PEACH_UTIL_SOURCE})
endif(BUILD_SHARED)

if(BUILD_STATIC)
    # Build these sources as libpeachutil (.so on Linux or .dll on Windows)
    add_library(peachutil STATIC ${PEACH_UTIL_SOURCE})
endif(BUILD_STATIC)

