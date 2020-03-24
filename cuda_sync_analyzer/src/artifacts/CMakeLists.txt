add_executable(hang_devsync hang_devsync.cu)
target_compile_options(hang_devsync PUBLIC -g -O0)
install(TARGETS hang_devsync
        RUNTIME DESTINATION bin)
