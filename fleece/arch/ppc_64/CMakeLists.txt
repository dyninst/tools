OPTION(ENABLE_PPC_64 "Enable ppc_64 architecture for testing" OFF)

IF(ENABLE_PPC_64)
    
    MESSAGE(STATUS "Enabled architecture: ppc_64")
    
    # Set the sources that should be compiled into the library
    SET(FLEECE_ARCH_SOURCE ${FLEECE_ARCH_SOURCE} ppc_64/arch_ppc_64.C PARENT_SCOPE) 

ENDIF()
