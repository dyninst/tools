# Set the sources that should be compiled into the library
set (FLEECE_UTIL_SOURCE Alias.C Architecture.C Bitfield.C BitTypeMap.C BitTypes.C Hashcounter.C Info.C MappedInst.C MapTable.C Mask.C Mystring.C Options.C RegisterSet.C)

# When binaries link against this library, which headers should be included?
include_directories (${PROJECT_SOURCE_DIR}/h})

# Build these sources as libfleeceutil (.so on Linux or .dll on Windows)
add_library(fleeceutil SHARED ${FLEECE_UTIL_SOURCE})

