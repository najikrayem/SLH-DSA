# Reference GenerateKeys
add_executable(GenerateKeys
    GenerateKeys.c
)
target_link_libraries(GenerateKeys
    slh_keygen
)
target_compile_options(GenerateKeys PRIVATE -ffunction-sections -fdata-sections)
target_link_options(GenerateKeys PRIVATE -Wl,--gc-sections)


# Armv8a Cortex-A72 GenerateKeys
add_executable(GenerateKeys_A72
    GenerateKeys.c
)
target_link_libraries(GenerateKeys_A72
    slh_keygen_A72
)
target_compile_options(GenerateKeys_A72 PRIVATE -march=armv8-a+crc -mtune=cortex-a72 -O3 -ffunction-sections -fdata-sections)
target_link_options(GenerateKeys_A72 PRIVATE -Wl,--gc-sections)



# Reference SignMessage
add_executable(SignMessage
    SignMessage.c
)
target_link_libraries(SignMessage
    slh_sign
)
target_compile_options(SignMessage PRIVATE -ffunction-sections -fdata-sections)
target_link_options(SignMessage PRIVATE -Wl,--gc-sections)


# Armv8a Cortex-A72 SignMessage
add_executable(SignMessage_A72
    SignMessage.c
)
target_link_libraries(SignMessage_A72
    slh_sign_A72
)
target_compile_options(SignMessage_A72 PRIVATE -march=armv8-a+crc -mtune=cortex-a72 -O3 -ffunction-sections -fdata-sections)
target_link_options(SignMessage_A72 PRIVATE -Wl,--gc-sections)


# Reference VerifySignature
add_executable(VerifySignature
    VerifySignature.c
)
target_link_libraries(VerifySignature
    slh_verify
)
target_compile_options(VerifySignature PRIVATE -ffunction-sections -fdata-sections)
target_link_options(VerifySignature PRIVATE -Wl,--gc-sections)


# Armv8a Cortex-A72 VerifySignature
add_executable(VerifySignature_A72
    VerifySignature.c
)
target_link_libraries(VerifySignature_A72
    slh_verify_A72
)
target_compile_options(VerifySignature_A72 PRIVATE -march=armv8-a+crc -mtune=cortex-a72 -O3 -ffunction-sections -fdata-sections)
target_link_options(VerifySignature_A72 PRIVATE -Wl,--gc-sections)


# -march=armv8-a+crc -mtune=cortex-a72 -O3 -ffunction-sections -fdata-sections