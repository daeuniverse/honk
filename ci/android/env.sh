#!/bin/sh
# Prints `export` lines for an Android NDK cross build of honk.
#
# Usage: eval "$(ci/android/env.sh aarch64-linux-android)"
#
# ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) must name an NDK r26 or newer;
# HONK_ANDROID_API selects the minimum API level (default 24, Android 7.0,
# the oldest level whose bionic exposes everything the workspace links).
# BoringSSL links the static libc++ so the binary runs from a root shell,
# where no app-private libc++_shared.so is on the loader path.
set -eu
target=${1:?usage: env.sh <aarch64-linux-android|x86_64-linux-android>}
ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
if [ -z "$ndk" ] || [ ! -f "$ndk/build/cmake/android.toolchain.cmake" ]; then
    echo "env.sh: set ANDROID_NDK_HOME to an Android NDK (r26+)" >&2
    exit 1
fi
api=${HONK_ANDROID_API:-24}
case "$target" in
    aarch64-linux-android) abi=arm64-v8a ;;
    x86_64-linux-android) abi=x86_64 ;;
    *) echo "env.sh: unsupported target $target" >&2; exit 1 ;;
esac
host=$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64
bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
var=$(echo "$target" | tr '-' '_')
upper=$(echo "$var" | tr '[:lower:]' '[:upper:]')
cat <<VARS
export ANDROID_NDK_HOME='$ndk'
export HONK_ANDROID_ABI='$abi'
export HONK_ANDROID_API='$api'
export CMAKE_TOOLCHAIN_FILE_$var='$here/toolchain.cmake'
export CC_$var='$bin/$target$api-clang'
export CXX_$var='$bin/$target$api-clang++'
export AR_$var='$bin/llvm-ar'
export CARGO_TARGET_${upper}_LINKER='$bin/$target$api-clang'
export BORING_BSSL_RUST_CPPLIB_$var='c++_static'
export CARGO_TARGET_${upper}_RUSTFLAGS='-C link-arg=-lc++abi'
export BINDGEN_EXTRA_CLANG_ARGS_$var='--sysroot=$ndk/toolchains/llvm/prebuilt/$host/sysroot --target=$target$api'
VARS
