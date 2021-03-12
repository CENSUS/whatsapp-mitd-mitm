#!/bin/bash

main()
{
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 FILENAME"
    else
        local tmp="$(mktemp -q)"

        dd if="$1" of="$tmp" bs=1 skip=8 &>/dev/null
        ./boringssl_session "$tmp" | ./openssl_session session.der
        rm "$tmp"

        openssl sess_id -inform DER -in session.der -outform PEM -out session.pem
        openssl sess_id -inform DER -in session.der -text
    fi
}

main "$@"
