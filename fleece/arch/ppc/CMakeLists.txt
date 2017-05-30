OPTION(ENABLE_PPC "Enable ppc architecture for testing" OFF)

IF(ENABLE_PPC)
    
    MESSAGE(STATUS "Enabled architecture: ppc")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_ARCH_SOURCE ${FLEECE_ARCH_SOURCE} ppc/arch_ppc.C PARENT_SCOPE) 

ENDIF()
