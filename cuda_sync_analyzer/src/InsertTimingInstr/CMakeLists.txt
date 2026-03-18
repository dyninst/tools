include_guard(GLOBAL)

set(_sources InsertTimingInstr.c cprof_buffer.c cprof_aggregator.c display.c)

set(_includes cprof_aggregator.h cprof_buffer.h display.h InsertTimingInstr.h)

add_library(CudaProfInstr SHARED ${_sources} ${_headers})
target_compile_options(CudaProfInstr PRIVATE -g -O3)
target_link_libraries(CudaProfInstr PUBLIC Threads::Threads)

install(
  TARGETS CudaProfInstr
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib/static)
