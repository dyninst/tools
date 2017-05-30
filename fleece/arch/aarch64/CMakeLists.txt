OPTION(ENABLE_AARCH64 "Enable aarch64 architecture for testing" OFF)

IF(ENABLE_AARCH64)
    
    MESSAGE(STATUS "Enabled architecture: aarch64")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_ARCH_SOURCE ${FLEECE_ARCH_SOURCE} aarch64/arch_aarch64.C PARENT_SCOPE) 

ENDIF()
