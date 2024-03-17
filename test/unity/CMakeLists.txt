add_library(unity_test_framework STATIC
    unity.c
)
target_include_directories(unity_test_framework PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(unity_test_framework PUBLIC
    UNITY_SUPPORT_64
)






