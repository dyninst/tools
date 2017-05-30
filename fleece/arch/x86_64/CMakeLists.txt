OPTION(ENABLE_X86_64 "Enable x86_64 architecture for testing" OFF)

IF(ENABLE_X86_64)
    
    MESSAGE(STATUS "Enabled architecture: x86_64")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_ARCH_SOURCE ${FLEECE_ARCH_SOURCE} x86_64/arch_x86_64.C PARENT_SCOPE) 

ENDIF()
