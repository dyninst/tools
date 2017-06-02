# Set the sources that should be compiled into the library
set (FLEECE_REPORTING_SOURCE Report.C ReportingContext.C)

# Build these sources as libfleecereporting (.so on Linux or .dll on Windows)
add_library(fleecereporting SHARED ${FLEECE_REPORTING_SOURCE})
target_include_directories(fleecereporting PUBLIC "${PROJECT_SOURCE_DIR}/h")

