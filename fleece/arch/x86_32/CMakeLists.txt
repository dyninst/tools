OPTION(ENABLE_X86_32 "Enable x86_32 architecture for testing" OFF)

IF(ENABLE_X86_32)
    
    MESSAGE(STATUS "Enabled architecture: x86_32")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_ARCH_SOURCE ${FLEECE_ARCH_SOURCE} x86_32/arch_x86_32.C x86_32/norm_x86_32.C PARENT_SCOPE) 

ENDIF()
