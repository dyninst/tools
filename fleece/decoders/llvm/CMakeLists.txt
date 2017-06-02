
IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    SET(LLVM_DIR "" CACHE STRING "Base directory for LLVM" FORCE)
ENDIF()

IF(NOT LLVM_DIR STREQUAL "")
    
    MESSAGE(STATUS "Using decoder: LLVM")
    
    # Set the sources that should be compiled into the library
    set (FLEECE_DECODER_SOURCE ${FLEECE_DECODER_SOURCE} llvm/llvm_common.C llvm/llvm_aarch64.C
    llvm/llvm_x86.C llvm/llvm_armv6.C llvm/llvm_ppc.C PARENT_SCOPE)

    SET(FLEECE_DECODER_LIBRARIES ${FLEECE_DECODER_LIBRARIES} 
        LLVMMC
        LLVMMCDisassembler
        LLVMX86Disassembler
        LLVMX86Desc
        LLVMARMDisassembler
        LLVMXCoreDisassembler
        LLVMXCoreDesc
        LLVMPowerPCDisassembler
        LLVMPowerPCDesc
        LLVMHexagonDisassembler
        LLVMSparcDisassembler
        LLVMSparcDesc
        LLVMSystemZDisassembler
        LLVMAArch64Disassembler
        LLVMAMDGPUDisassembler
        LLVMMipsDisassembler
        LLVMMipsDesc
        LLVMNVPTXDesc
        LLVMMSP430Desc
        LLVMBPFDesc
    PARENT_SCOPE)

    SET(DECODER_INSTALL_DIRS ${DECODER_INSTALL_DIRS} ${LLVM_DIR} PARENT_SCOPE)

ENDIF()
