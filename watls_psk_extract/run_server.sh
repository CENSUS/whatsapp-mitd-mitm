#!/bin/bash

start_server()
{
    psk="4141414141414141414141414141414141414141414141414141414141414141"

    [ -n "$1" ] && psk="$1"

    echo "Using PSK $psk"

    #
    # In the following, we use OpenSSL's -HTTP option to serve files containing
    # custom HTTP headers. You can replace it with either -WWW or -www to
    # implement your own hacks, however, if you need normal s_server I/O you
    # must use -ign_eof and -early_data.
    #
    # Set the USE_SYSTEM environment variable to use system's OpenSSL instead of
    # the modified one. This is more or less meaningless, unless you want to
    # debug OpenSSL internals.
    #
    if [ -z "$USE_SYSTEM" ]; then
        echo "Running WaTLS version"

        #
        # In order to execute our modified OpenSSL in-place, we need to preserve
        # LD_LIBRARY_PATH in the new sudo environment. This is generally not allowed,
        # unless sudo has been explicitly configured to allow so. To avoid spending
        # time debugging environment issues (like I did), configure and compile
        # OpenSSL as shown below:
        #
        # ./config -d no-shared && make -j8
        #
        if [ "$(uname)" = "Darwin" ]; then
            export DYLD_LIBRARY_PATH="$OPENSSL_SRC"
        else
            export LD_LIBRARY_PATH="$OPENSSL_SRC"
        fi
        sudo -sE "$OPENSSL_SRC/apps/openssl" s_server \
            -tls1_3 \
            -port 443 \
            -cert "$SECRETS/cert.pem" \
            -key "$SECRETS/key.pem" \
            -ciphersuites TLS_AES_128_GCM_SHA256 \
            -psk "$psk" \
            -legacy_renegotiation \
            -no_dhe \
            -no_ticket \
            -stateless \
            -WWW
    else
        echo "Running system version"
        sudo openssl s_server \
            -tls1_3 \
            -port 443 \
            -cert "$SECRETS/cert.pem" \
            -key "$SECRETS/key.pem" \
            -ciphersuites TLS_AES_128_GCM_SHA256 \
            -psk "$psk" \
            -legacy_renegotiation \
            -no_dhe \
            -no_ticket \
            -stateless \
            -WWW
    fi
}


main()
{
    #
    # Path to the OpenSSL source code patched with our TLS 1.2 MitM patch.
    #
    if [ -z "$OPENSSL_SRC" ]; then
        echo "OPENSSL_SRC not set!"
        return
    fi

    #
    # Path to the directory containing "cert.pem" and "key.pem".
    #
    if [ -z "$SECRETS" ]; then
        echo "SECRETS not set!"
        return
    fi

    #
    # Start the MitM OpenSSL server.
    #
    start_server "$1"
}


main "$@"

# EOF

