add_executable(IFSVerifyMount
    IFSVerifyMount.c
)
target_link_libraries(IFSVerifyMount
    slh_verify
)
target_compile_options(IFSVerifyMount PRIVATE -ffunction-sections -fdata-sections)
target_link_options(IFSVerifyMount PRIVATE -Wl,--gc-sections)


# add_custom_command(
#     OUTPUT "sample_ifs.bin"
#     COMMAND "PROCESSOR=aarch64le mkifs -vvvv example/qnx_ifs_verify_mount/sample_ifs.bf example/qnx_ifs_verify_mount/sample_ifs.bin"
#     DEPENDS "IFSVerifyMount.c" "sample_ifs.bin"
# )

add_custom_command(
    OUTPUT "sample_ifs.bin"
    COMMAND ${CMAKE_COMMAND} -E env PROCESSOR=aarch64le mkifs -vvvv example/qnx_ifs_verify_mount/sample_ifs.bf example/qnx_ifs_verify_mount/sample_ifs.bin
    DEPENDS "IFSVerifyMount.c" "sample_ifs.bin"
)
