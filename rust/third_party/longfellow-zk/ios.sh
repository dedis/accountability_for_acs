#!/bin/bash
set -e

# Create build directory
mkdir -p build-ios-arm64 deps-ios

# Build dependencies. This script assumes the
# android script has already run to download the packages.

# 1. googletest
if [ ! -d "googletest" ]; then
   echo "Run or inspect the android.sh script to download all dependencies"
fi

cd googletest
mkdir -p build-ios-arm64
cmake -B build-ios-arm64 \
    -G Xcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$(pwd)/../deps-ios
cmake --build build-ios-arm64 --target install --config Release
cd ..

# 2. benchmark
cd benchmark
mkdir -p build-ios-arm64
# Configure with CMake
cmake -B build-ios-arm64 \
    -G Xcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DBENCHMARK_ENABLE_TESTING=OFF \
    -DBENCHMARK_ENABLE_GTEST_TESTS=OFF \
    -DCMAKE_INSTALL_PREFIX=$(pwd)/../deps-ios

cmake --build build-ios-arm64 --target install --config Release
cd ..

# 3. zstd
cd zstd
mkdir -p build-ios-arm64
cmake -B build-ios-arm64 -S build/cmake \
    -G Xcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$PWD/../deps-ios \
    -DZSTD_BUILD_PROGRAMS=OFF \
    -DZSTD_BUILD_TESTS=OFF \
    -DZSTD_BUILD_SHARED=OFF

cmake --build build-ios-arm64 --target install --config Release
cd ..

# 4. openssl
cd openssl
make clean
./Configure ios64-xcrun --prefix=$PWD/../deps-ios \
    no-autoalginit no-autoerrinit no-tls no-dtls no-legacy no-apps no-docs no-autoload-config no-quic \
    no-zlib no-http no-threads no-mdc2 no-ui-console no-winstore \
    no-idea no-cast no-poly1305 no-siphash no-cmac no-chacha no-cmp no-cms no-comp no-blake2 no-gost no-whirlpool no-camellia no-rc2 no-rc4 no-md4 no-ml-dsa no-ml-kem no-argon2 no-aria no-dsa no-scrypt no-sm2 no-sm3 no-sm4 no-sock no-srp no-srtp no-ssl-trace no-unstable-qlog no-uplink no-dso no-multiblock

make -j 12
make install_sw
cd ..

# Finally build longfellow-zk

cmake -S lib -B build-ios-arm64 \
    -G Xcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_FIND_ROOT_PATH=$PWD/deps-ios \
    -DCMAKE_XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER=com.example.longfellow  \
    -DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM="YW2B85PHLW"

# Build
cmake --build build-ios-arm64 --config Release -- -allowProvisioningUpdates

