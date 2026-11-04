# NDK toolchain wrapper for boring-sys Android cross builds (ci/android/env.sh).
#
# boring-sys hands BoringSSL to CMake without its own Android defines when a
# toolchain file is supplied, so this file carries them. BUILD_TESTING is off
# because Google Benchmark's regex feature probe uses try_run, which cannot run
# a target binary on the build host and fails configuration outright.
set(ANDROID_ABI "$ENV{HONK_ANDROID_ABI}" CACHE STRING "")
set(ANDROID_PLATFORM "android-$ENV{HONK_ANDROID_API}" CACHE STRING "")
set(ANDROID_STL c++_static CACHE STRING "")
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
include("$ENV{ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake")
