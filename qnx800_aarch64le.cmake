set(CMAKE_SYSTEM_NAME QNX)

set(arch gcc_ntoaarch64le)
set(QNX_PROCESSOR armv8-a)

set(CMAKE_C_COMPILER qcc)
set(CMAKE_C_COMPILER_TARGET ${arch})

set(CMAKE_SYSROOT $ENV{QNX_TARGET})