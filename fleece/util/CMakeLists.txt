# Set the sources that should be compiled into the library
set (FLEECE_UTIL_SOURCE Architecture.C Assembly.C Bitfield.C BitTypes.C 
FieldList.C FindList.C Info.C MappedInsn.C Mask.C Reassemble.C StringUtils.C Options.C 
ReassemblyDaemon.C
RegisterSet.C SimpleInsnMap.C)

# When binaries link against this library, which headers should be included?
include_directories (${PROJECT_SOURCE_DIR}/h})

# Build these sources as libfleeceutil (.so on Linux or .dll on Windows)
add_library(fleeceutil SHARED ${FLEECE_UTIL_SOURCE})

