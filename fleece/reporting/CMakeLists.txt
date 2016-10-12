# Set the sources that should be compiled into the library
set (FLEECE_REPORTING_SOURCE Report.C ReportingContext.C)

# When binaries link against this library, which headers should be included?
include_directories (${PROJECT_SOURCE_DIR}/h})

# Build these sources as libfleecereporting (.so on Linux or .dll on Windows)
add_library(fleecereporting SHARED ${FLEECE_REPORTING_SOURCE})

