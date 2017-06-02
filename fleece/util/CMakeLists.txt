# Set the sources that should be compiled into the library
set (FLEECE_UTIL_SOURCE Assembly.C Bitfield.C 
FieldList.C FindList.C Info.C MappedInsn.C Mask.C Reassemble.C StringUtils.C Options.C 
ReassemblyDaemon.C
RegisterSet.C SimpleInsnMap.C)

# Build these sources as libfleeceutil (.so on Linux or .dll on Windows)
add_library(fleeceutil SHARED ${FLEECE_UTIL_SOURCE})
target_include_directories(fleeceutil PUBLIC "${PROJECT_SOURCE_DIR}/h")

