set_source_files_properties(KECCAK.S PROPERTIES LANGUAGE ASM)

add_library(keccak_armv8a_cortexa72 OBJECT KECCAK.S)

if(CMAKE_SYSTEM_NAME STREQUAL "QNX")
    target_compile_options(keccak_armv8a_cortexa72 PUBLIC -Vgcc_ntoaarch64le -vv)
endif()


#target_compile_options(keccak_armv8a_cortexa72 PUBLIC -march=armv8-a -mtune=cortex-a72 -mabi=aapcs -v)

target_include_directories(keccak_armv8a_cortexa72 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(keccak_armv8a_cortexa72 PUBLIC)

#make sure the include directory is included in the build by printing the include directories
get_target_property(keccak_armv8a_cortexa72_includes keccak_armv8a_cortexa72 INCLUDE_DIRECTORIES)
message(STATUS "keccak_armv8a_cortexa72 include directories: ${keccak_armv8a_cortexa72_includes}")