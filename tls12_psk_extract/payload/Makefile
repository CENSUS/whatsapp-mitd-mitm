OBJS=libwhatsapp.o
BIN=libwhatsapp.so

CFLAGS=-Wall -O2 -g -fPIC
LDFLAGS=-shared -landroid -llog

CC=$(CROSS_COMPILE)clang

all: env $(OBJS)
	$(CC) $(OBJS) -o $(BIN) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BIN) payload.zip

.PHONY: env
env:
	@if [ -z "$$CROSS_COMPILE" ]; then echo "CROSS_COMPILE not set!"; exit 1; fi

