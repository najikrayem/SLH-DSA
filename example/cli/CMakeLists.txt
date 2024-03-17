add_executable(GenerateKeys
    GenerateKeys.c
)
target_link_libraries(GenerateKeys
    slh_keygen
)
target_compile_options(GenerateKeys PRIVATE -ffunction-sections -fdata-sections)
target_link_options(GenerateKeys PRIVATE -Wl,--gc-sections)



add_executable(SignMessage
    SignMessage.c
)
target_link_libraries(SignMessage
    slh_sign
)
target_compile_options(SignMessage PRIVATE -ffunction-sections -fdata-sections)
target_link_options(SignMessage PRIVATE -Wl,--gc-sections)



add_executable(VerifySignature
    VerifySignature.c
)
target_link_libraries(VerifySignature
    slh_verify
)
target_compile_options(VerifySignature PRIVATE -ffunction-sections -fdata-sections)
target_link_options(VerifySignature PRIVATE -Wl,--gc-sections)