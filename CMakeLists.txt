cmake_minimum_required(VERSION 3.22.1)

# Set the project name
project(SLH_DSA LANGUAGES C)

# Add compiler flags
#add_compile_options(-march=armv8-a)

# GDB TODO
set(CMAKE_BUILD_TYPE Debug)

# Add the implementation subdirectory
add_subdirectory(slh-dsa)

# Add the example subdirectory
add_subdirectory(example)



