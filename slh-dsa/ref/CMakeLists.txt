add_subdirectory(SHAKE256)

add_library(random OBJECT
    random.c
)

add_library(slh_common OBJECT
    slh_common.c
)

add_library(slh_hash OBJECT
    slh_hash.c
)

add_library(slh_keygen STATIC
    slh_keygen.c
)
link_libraries(slh_keygen
    shake256
)


add_library(slh_sign OBJECT
    slh_sign.c
)

add_library(slh_verify OBJECT
    slh_verify.c
)