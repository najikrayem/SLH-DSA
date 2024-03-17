add_subdirectory(unity)

link_libraries(unity_test_framework slh_common slh_sign slh_hash)


add_executable(slh_common_test
    slh_common_test.c
)

add_executable(slh_sign_test
    slh_sign_test.c
)

add_executable(slh_hash_test
    slh_hash_test.c
)

add_executable(slh_ds_test
    slh_ds_test.c
)
