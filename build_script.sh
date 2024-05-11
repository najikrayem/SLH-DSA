
# Check if the build directory exists. If it does, remove it
if [ -d "build" ]; then
    rm -rf build
fi

# Check target architecture input argument. Should be either aarch64_unix, x86_64_unix, or aaarch64_qnx
if [ "$1" = "aarch64_unix" ]; then

    export PROCESSOR="aarch64le"
    cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=linux_arm.cmake

elif [ "$1" = "x86_64_unix" ]; then
    
    export PROCESSOR="x86_64"
    cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=linux_x86_64.cmake

elif [ "$1" = "aarch64_qnx" ]; then
    
    export PROCESSOR="aarch64le"
    cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=qnx800_aarch64le.cmake

else
    echo "Invalid target architecture. Please use either aarch64_unix, x86_64_unix, or aarch64_qnx"
    exit 1
fi

cd build
make verbose=3

