add_subdirectory(SHAKE256)

add_library(random OBJECT
    random.c
)


# reference hash
add_library(slh_hash STATIC
    slh_hash.c
)
target_link_libraries(slh_hash
    ref_shake256
    $<TARGET_OBJECTS:ref_shake256>
)



# Armv8 Cortex-a72 optimized hash
add_library(slh_hash_A72 STATIC
    slh_hash.c
)
target_link_libraries(slh_hash_A72
    armv8a_cortexa72_shake256
    $<TARGET_OBJECTS:armv8a_cortexa72_shake256>
)
target_compile_options(slh_hash_A72 PRIVATE)



# Reference common
add_library(slh_common STATIC
    slh_common.c
)
target_include_directories(slh_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_common PUBLIC
    slh_hash
    random
    m
)


# Armv8 Cortex-a72 optimized common
add_library(slh_common_A72 STATIC
    slh_common.c
)
target_include_directories(slh_common_A72 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_common_A72 PUBLIC
    slh_hash_A72
    random
    m
)
target_compile_options(slh_common_A72 PRIVATE)



# Reference keygen
add_library(slh_keygen STATIC
    slh_keygen.c
)
target_include_directories(slh_keygen PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_keygen
    slh_common
)


# Armv8 Cortex-a72 optimized keygen
add_library(slh_keygen_A72 STATIC
    slh_keygen.c
)
target_include_directories(slh_keygen_A72 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_keygen_A72 PUBLIC
    slh_common_A72
)
target_compile_options(slh_keygen_A72 PRIVATE)



# Reference sign
add_library(slh_sign STATIC
    slh_sign.c
)
target_include_directories(slh_sign PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_sign
    slh_common
)

# Armv8 Cortex-a72 optimized sign
add_library(slh_sign_A72 STATIC
    slh_sign.c
)
target_include_directories(slh_sign_A72 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_sign_A72 PUBLIC
    slh_common_A72
)
target_compile_options(slh_sign_A72 PRIVATE)


# Reference verify
add_library(slh_verify STATIC
    slh_verify.c
)
target_include_directories(slh_verify PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_verify
    slh_common
)


# Armv8 Cortex-a72 optimized verify
add_library(slh_verify_A72 STATIC
    slh_verify.c
)
target_include_directories(slh_verify_A72 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(slh_verify_A72 PUBLIC
    slh_common_A72
)
target_compile_options(slh_verify_A72 PRIVATE)