# Set the sources that should be compiled into the library
set (FLEECE_REPORTING_SOURCE ReportingContext.C)

# When binaries link against this library, which headers should be included?
include_directories (${PROJECT_SOURCE_DIR}/h})

if(BUILD_SHARED)
    # Build these sources as libfleecereporting (.so on Linux or .dll on Windows)
    add_library(fleecereporting SHARED ${FLEECE_REPORTING_SOURCE})
endif(BUILD_SHARED)

if(BUILD_STATIC)
    # Build these sources as libfleecereporting (.so on Linux or .dll on Windows)
    add_library(fleecereporting STATIC ${FLEECE_REPORTING_SOURCE})
endif(BUILD_STATIC)

