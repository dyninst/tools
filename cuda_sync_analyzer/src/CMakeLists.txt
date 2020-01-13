add_compile_options(-O3 -g)

file(GLOB src "*.cpp")
add_library(cuda_sync_analyzer SHARED ${src})
configure_file (
    "SyncDriverVerisons.txt"
    "${CMAKE_INSTALL_PREFIX}/lib/SyncDriverVerisons.txt"
)
configure_file (
    "${PROJECT_SOURCE_DIR}/src/Constants.h.in"
    "${PROJECT_SOURCE_DIR}/src/Constants.h"
)
target_link_libraries(cuda_sync_analyzer PUBLIC "-lcrypto\
    -L${BOOST_LIBRARYDIR} -lboost_program_options -lboost_filesystem -lboost_system\
    ${DYNINST_LIBRARIES}")
    #    -L${CUDA_TOOLKIT_ROOT_DIR}/lib64\
target_include_directories(cuda_sync_analyzer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
install(TARGETS cuda_sync_analyzer
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static
        RUNTIME DESTINATION bin)
add_subdirectory(FindSyncHelper)
add_subdirectory(InsertTimingInstr)
