add_library(ref_shake256 OBJECT
    fips202.c
)
target_include_directories(ref_shake256 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)




# ARMv8-A Cortex-A72
add_library(armv8a_cortexa72_shake256 STATIC
    fips202.c
)
target_link_libraries(armv8a_cortexa72_shake256 PUBLIC
    keccak_armv8a_cortexa72
)
target_include_directories(armv8a_cortexa72_shake256 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../armv8/SHAKE256/ 
)
target_compile_definitions(armv8a_cortexa72_shake256 PRIVATE "ARMV8A_CORTEXA72_OPTIMIZED")


