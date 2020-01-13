add_compile_options(-O3 -g)
#add_compile_options(-mno-vsx)
add_library(InsertTimingInstr SHARED "InsertTimingInstr.cpp")
install(TARGETS InsertTimingInstr
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)
