OPTION(ENABLE_ARMV6 "Enable armv6 architecture for testing" OFF)

IF(ENABLE_ARMV6)
    
    MESSAGE(STATUS "Enabled architecture: armv6")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_ARCH_SOURCE ${FLEECE_ARCH_SOURCE} armv6/arch_armv6.C PARENT_SCOPE) 

ENDIF()
