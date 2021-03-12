#!/system/bin/sh

main()
{
    local apk="$(pm path com.whatsapp | cut -d ":" -f 2)"

    [ -z "$apk" ] && (echo "WhatsApp APK path not found"; return)

    CLASSPATH="classes.dex:$apk" app_process / WatlsPskExtract "$@"
}

main "$@"

