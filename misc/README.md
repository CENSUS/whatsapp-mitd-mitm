# Debugging scripts

This directory contains various scripts that were used for debugging purposes
during our research. We provide them for reference purposes. Don't expect
everything here to work out of the box.

* **sniff.js** - WhatsApp XMPP packet sniffer. Available for 2.19.355, 2.20.200.22
  and 2.20.206.22.

* **watls\_unzip\_trigger.js** - Triggers the `FilterManager` unzip vulnerability
  in a kinda unorthodox way. It uses WhatsApp's media downloader, which by
  default uses TLS v1.3 (WaTLS), in order to download a ZIP file from a server
  controlled by the attacker. However, it makes WhatsApp think that WaTLS is
  disabled, forcing the media downloader to fall back to using TLS v1.2. The
  downloaded ZIP file is then passed to `FilterManager` and the path traversal
  vulnerability is triggered. I wrote this script while developing the unzip PoC.
  Available for 2.19.355 and 2.20.206.22.

* **extssl_download.js** - Forces WhatsApp to connect to a couple of its TLS v1.2
  servers thus forcing it to refresh the PSKs stored in the device's external
  storage. Available for 2.19.355, 2.20.200.22 and 2.20.206.22.

* **watls_download.js** - Forces WhatsApp to connect to a TLS v1.3 media download
  server and hooks part of the WaTLS engine, in order to dump TLS secrets to the
  console. Available for 2.19.355 and 2.20.206.22.

* **dump_hprof.js** - Uses `android.os.Debug::dumpHprofData()` (used by WhatsApp's
  internal OOM handler) to dump heap data under **/data/data/com.whatsapp**. The
  heap contents can be examined to recover the user's Noise key pair (both public
  and private key) as found in **/data/data/com.whatsapp/shared_prefs/keystore.xml**.

