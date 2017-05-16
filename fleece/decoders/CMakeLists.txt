# Set the sources that should be compiled into the library
set (FLEECE_DECODERS_SOURCE aarch64_common.C Decoder.C dyninst_aarch64.C dyninst_x86_64.C dyninst_x86_32.C dyninst_armv6.C gnu_aarch64.C
gnu_x86_32.C gnu_x86_64.C gnu_ppc.C gnu_ppc_32.C
llvm_aarch64.C llvm_common.C llvm_x86_32.C llvm_x86_64.C llvm_armv6.C Normalization.C null_decoders.C xed_x86_32.C xed_x86_64.C capstone_aarch64.C
capstone_x86_32.C capstone_x86_64.C capstone_ppc.C llvm_ppc.C dyninst_ppc.C dyninst_ppc_32.C llvm_ppc_32.C) 
# When binaries link against this library, which headers should be included?
include_directories ("${PROJECT_SOURCE_DIR}/h")

# Build these sources as libfleecedecoders (.so on Linux or .dll on Windows)
add_library(fleecedecoders SHARED ${FLEECE_DECODERS_SOURCE})
