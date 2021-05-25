.rodata

.global dex_start
.balign 4
dex_start:
.incbin "../key_extractor/classes.dex"

.global dex_end
.balign 1
dex_end:
.byte 0

