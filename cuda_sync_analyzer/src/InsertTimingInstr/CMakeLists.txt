#add_compile_options(-mno-vsx)
add_library(CudaProfInstr SHARED InsertTimingInstr.c diog_buffer.c diog_aggregator.c display.c)
target_compile_options(CudaProfInstr PUBLIC -g -O3 -pthread)
install(TARGETS CudaProfInstr
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)
