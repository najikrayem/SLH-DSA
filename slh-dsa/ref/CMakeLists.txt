add_subdirectory(SHAKE256)

add_library(random OBJECT
    random.c
)



add_library(slh_hash OBJECT
    slh_hash.c
)
target_link_libraries(slh_hash
    ref_shake256
    $<TARGET_OBJECTS:ref_shake256>
)



add_library(slh_common STATIC
    slh_common.c
)
target_link_libraries(slh_common
    slh_hash
    random
)
target_link_options(slh_common PUBLIC
    -lm
)



add_library(slh_keygen STATIC
    slh_keygen.c
)
target_include_directories(slh_keygen PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_keygen
    slh_common
)



add_library(slh_sign STATIC
    slh_sign.c
)
target_link_libraries(slh_sign
    slh_common
)



add_library(slh_verify STATIC
    slh_verify.c
)
target_link_libraries(slh_verify
    slh_common
)