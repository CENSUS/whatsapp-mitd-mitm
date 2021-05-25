include ../Makefile.config

OBJS=dex.o log.o stub.o
BIN=stub.so

HOST_TAG=$(shell uname -sm | tr "A-Z " a-z-)

CC=$(NDK_PATH)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin/clang

CFLAGS=-Wall -O2 -g -target aarch64-linux-android28 \
	-fPIC -fno-builtin -fvisibility=default

LDFLAGS=-Wl,-soname=libvlc.so -target aarch64-linux-android28 \
	-shared -llog -landroid -pthread

payload: stub
	./create_zip.sh &>/dev/null

stub: $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LDFLAGS)

dex.o: dex.S ../key_extractor/classes.dex

log.o: log.c log.h

stub.o: stub.c stub.h

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

%.o: %.S
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJS) $(BIN) payload.zip

