add_subdirectory(unity)

link_libraries(unity_test_framework slh_common)


add_executable(slh_common_test
    slh_common_test.c
)


add_executable(slh_ds_test
    slh_ds_test.c
)
