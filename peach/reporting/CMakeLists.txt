# Set the sources that should be compiled into the library
set (PEACH_REPORTING_SOURCE ReportingContext.C)

# When binaries link against this library, which headers should be included?
include_directories (${PROJECT_SOURCE_DIR}/h})

if(BUILD_SHARED)
    # Build these sources as libpeachreporting (.so on Linux or .dll on Windows)
    add_library(peachreporting SHARED ${PEACH_REPORTING_SOURCE})
endif(BUILD_SHARED)

if(BUILD_STATIC)
    # Build these sources as libpeachreporting (.so on Linux or .dll on Windows)
    add_library(peachreporting STATIC ${PEACH_REPORTING_SOURCE})
endif(BUILD_STATIC)

