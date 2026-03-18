include_guard(GLOBAL)

add_library(FindSyncHelper SHARED FindSyncHelper.cpp)
target_compile_options(FindSyncHelper PRIVATE -O3 -g)

install(
  TARGETS FindSyncHelper
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib/static)
