cmake_minimum_required(VERSION 3.12)

# Set the project name
project(SLH_DSA)

# # Define an option to enable/disable building examples
# option(BUILD_EXAMPLES "Build example programs" ON)

# # Define an option to enable/disable building tests
# option(BUILD_TESTS "Build test programs" ON)

# # 

# # Add "example" subdirectory only if option BUILD_EXAMPLES is enabled
# if(BUILD_EXAMPLES)
#     add_subdirectory(example)
# endif

# # Add "test" subdirectory only if option BUILD_TESTS is enabled
# if(BUILD_TESTS)
#     add_subdirectory(test)
# endif

# example programs
add_subdirectory(example)

# test programs
add_subdirectory(test)

# Add the implementation subdirectory
add_subdirectory(slh-dsa)



