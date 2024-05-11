# armv8 optimized implementation

# Check if the PROCESSOR environment variable is "aarch64le"
if (DEFINED ENV{PROCESSOR} AND $ENV{PROCESSOR} STREQUAL "aarch64le")
    add_subdirectory(armv8)
endif()

# reference implementation
add_subdirectory(ref)


