add_library(ref_shake256 OBJECT
    fips202.c
)
target_include_directories(ref_shake256 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)