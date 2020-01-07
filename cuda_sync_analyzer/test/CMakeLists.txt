add_compile_options(-O3 -g)

add_executable(main main.cpp)

link_directories(${CMAKE_BINARY_DIR}/src)
target_link_libraries(main LINK_PUBLIC "cuda_sync_analyzer")
install(TARGETS main
        RUNTIME DESTINATION bin)
