include_guard(GLOBAL)

if(NOT CMAKE_CUDA_ARCHITECTURES)
  set(CMAKE_CUDA_ARCHITECTURES 70)
endif()

message(STATUS "Using CUDA architectures ${CMAKE_CUDA_ARCHITECTURES}.")
message(STATUS "Set CMAKE_CUDA_ARCHITECTURES to change.") 


add_executable(hang_devsync hang_devsync.cu)
target_compile_options(hang_devsync PUBLIC -g -O0)

install(TARGETS hang_devsync RUNTIME DESTINATION bin)
