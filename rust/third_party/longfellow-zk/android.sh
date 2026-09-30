#!/bin/bash
set -e

# Ensure ANDROID_NDK_ROOT is set
if [ -z "$ANDROID_NDK_ROOT" ]; then
  echo "Please set ANDROID_NDK_ROOT environment variable."
  exit 1
fi

# Create deps directory if it doesn't exist
mkdir -p deps-android

# 1. Build GoogleTest
echo "Building Benchmark for Android..."
if [ ! -d "googletest" ]; then
  echo "Cloning googletest repository..."
  git clone --depth 1  https://github.com/google/googletest.git
fi
echo "Building GoogleTest for Android..."
cd googletest
rm -rf build-android
cmake -B build-android \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI="arm64-v8a" \
      -DANDROID_PLATFORM=android-24 \
      -DCMAKE_INSTALL_PREFIX=$PWD/../deps-android \
      -DBUILD_GTEST=ON \
      -DBUILD_GMOCK=ON \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-android --target install --parallel 8
cd ..

# 2. Build Benchmark
echo "Building Benchmark for Android..."
if [ ! -d "benchmark" ]; then
  echo "Cloning benchmark repository..."
  git clone --depth 1 https://github.com/google/benchmark.git
fi

cd benchmark
rm -rf build-android
cmake -B build-android \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI="arm64-v8a" \
      -DANDROID_PLATFORM=android-24 \
      -DCMAKE_INSTALL_PREFIX=$PWD/../deps-android \
      -DBENCHMARK_ENABLE_GTEST_TESTS=OFF \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-android --target install --parallel 8
cd ..

# 2.5 Build zstd
echo "Building zstd for Android..."
if [ ! -d "zstd" ]; then
  echo "Cloning zstd repository..."
  git clone --depth 1 https://github.com/facebook/zstd.git
fi
cd zstd
rm -rf build-android
cmake -B build-android \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI="arm64-v8a" \
      -DANDROID_PLATFORM=android-24 \
      -DCMAKE_INSTALL_PREFIX=$PWD/../deps-android \
      -DBENCHMARK_ENABLE_GTEST_TESTS=OFF \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-android --target install --parallel 8
cd ..

# 2.8 Build openssl
echo "Building openssl for Android..."
if [ ! -d "openssl" ]; then
   echo "Cloning openssl"
   git clone --depth 1 https://github.com/openssl/openssl.git 
fi
cd openssl
PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin:$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.9/prebuilt/darwin-x86_64/bin:$PATH 
CFLAGS=-Wno-macro-redefined ./Configure android-arm64 -D__ANDROID_API__=29 --prefix=$PWD/../deps-android \
        no-autoalginit no-autoerrinit no-tls no-dtls no-legacy no-apps no-docs no-autoload-config no-quic \
        no-zlib no-http no-threads no-mdc2 no-ui-console no-winstore \
  	no-idea no-cast no-poly1305 no-siphash no-cmac no-chacha no-cmp no-cms no-comp no-blake2 no-gost no-whirlpool no-camellia no-rc2 no-rc4 no-md4 no-ml-dsa no-ml-kem no-argon2 no-aria no-dsa no-scrypt no-slh-dsa no-sm2 no-sm3 no-sm4 no-sock no-srp no-siphash no-srtp no-siphash no-ssl-trace no-unstable-qlog no-uplink no-dso no-multiblock no-tls1_1 no-tls1_2
make -j 12 install 
cd ..


# Remove shared libraries from deps to force static linking
echo "Removing shared libraries from deps to force static linking..."
rm -f deps-android/lib/*.so

# 3. Build Main Project Tests
echo "Building Main Project Tests for Android..."
rm -rf build-android-arm64
cmake -S lib -B build-android-arm64 \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI="arm64-v8a" \
      -DANDROID_PLATFORM=android-24 \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_FIND_ROOT_PATH=$PWD/deps-android

cmake --build build-android-arm64 --config Release --parallel 8
