#!/bin/sh
addr2line=/media/marcel/C720/android-ndk-r10e/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi-addr2line
lib=./app/build/intermediates/binaries/debug/all/obj/armeabi-v7a/libnetguard.so
addr2line -C -f -e $lib $1
