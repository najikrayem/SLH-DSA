rm -rf build

cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=qnx800_aarch64le.cmake

#cmake -G "Unix Makefiles" -S . -B build -DCMAKE_TOOLCHAIN_FILE=linux_x86_64.cmake

cd build
make #verbose=1
cd ..
