rm -rf build

export PROCESSOR="aarch64le"

cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=qnx800_aarch64le.cmake

#cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=linux_x86_64.cmake

#cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=linux_arm.cmake

cd build
make verbose=3
cd ..
