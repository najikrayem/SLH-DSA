cmake_minimum_required(VERSION 3.22.1)

# Set the project name
project(SLH_DSA LANGUAGES C ASM)

# Add compiler flags
#add_compile_options(-march=armv8-a)

# GDB TODO
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O3")

set(CMAKE_USE_RELATIVE_PATHS ON)

# set verbose makefile
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

# Define the option to strip the binary
option(STRIP_BINARY "Strip the binary" ON)
# Strip the binary if the option is ON and the build type is NOT Debug
if(STRIP_BINARY AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")
else()
    message(STATUS "Stripping the binary is disabled because the build type is Debug")
endif()


# Define the instrumentation option
option(INSTRUMENTATION "Enable instrumentation" OFF)
# Link the instrumentation library to all targets if the option is ON
if(INSTRUMENTATION)
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_options(-finstrument-functions)
    add_compile_options(-fno-eliminate-unused-debug-symbols)
    add_definitions(-DINSTRUMENTATION_ENABLED)
    set(CMAKE_ENABLE_EXPORTS true)

    add_library(cyg_instr STATIC test/cyg_instrumentation.c)
    # check if CMAKE_SYSTEM_NAME is linux
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Linux system detected; linking dl library")
        target_link_libraries(cyg_instr PUBLIC dl)
        target_link_options(cyg_instr PUBLIC -ldl)
    endif()

    link_libraries(cyg_instr dl)
endif()


# Add the implementation subdirectory
add_subdirectory(slh-dsa)

# Add the example subdirectory
add_subdirectory(example)

# Add the test subdirectory
add_subdirectory(test)






