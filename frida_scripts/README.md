# Frida scripts

This directory holds Frida scripts used by the PoC.

**version.js** determines the WhatsApp version. Once the version is read, the
PoC loads Frida scripts from **whatsapp-`version`/**.

**whatsapp-`version`/phish.js** takes care of the phishing part described in our
blog post.

Most of the tooling in this repository was originally developed for 2.19.355,
which, at some point, stopped working. WhatsApp implements custom expiration
checks which prohibit users from using old versions. To continue working without
disrupting our research, we had to bypass those expiration checks, and this is
exactly what **whatsapp-2.19.355/expire.js** does.

Later, however, we updated the PoC and made it work with 2.20.206.22. Users
wishing to experiment with our work should consider using this version instead.

