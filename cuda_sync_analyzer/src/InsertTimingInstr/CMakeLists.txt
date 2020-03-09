add_compile_options(-g)
#add_compile_options(-mno-vsx)
add_library(InsertTimingInstr SHARED InsertTimingInstr.c diog_buffer.c diog_aggregator.c)
target_compile_options(InsertTimingInstr PUBLIC -pthread)
install(TARGETS InsertTimingInstr
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)
