CFLAGS=-Wall -O2 -g
OPENSSL_INCLUDES=-I $(OPENSSL_SRC) -I $(OPENSSL_SRC)/include
# OPENSSL_LIBS=-L $(OPENSSL_SRC) -lssl -lcrypto
OPENSSL_LIBS=$(OPENSSL_SRC)/libssl.a $(OPENSSL_SRC)/libcrypto.a -pthread -ldl

CXXFLAGS=-std=c++11 -Wall -O2 -g
BORINGSSL_INCLUDES=-I $(BORINGSSL_SRC) -I $(BORINGSSL_SRC)/include
BORINGSSL_LIBS=$(BORINGSSL_SRC)/build/ssl/libssl.a $(BORINGSSL_SRC)/build/crypto/libcrypto.a -pthread

all: env openssl_session boringssl_session

openssl_session: env
	$(CC) openssl_session.c $(OPENSSL_INCLUDES) $(CFLAGS) -o openssl_session $(OPENSSL_LIBS)

boringssl_session: env
	$(CC) boringssl_session.cpp $(BORINGSSL_INCLUDES) $(CXXFLAGS) -o boringssl_session $(BORINGSSL_LIBS)

.PHONY:
clean:
	rm -f openssl_session boringssl_session session.der session.pem downloadable* sticker* payload.zip

.PHONY: env
env:
	@if [ -z "$$OPENSSL_SRC" ]; then echo "OPENSSL_SRC not set!"; exit 1; fi
	@if [ -z "$$BORINGSSL_SRC" ]; then echo "BORINGSSL_SRC not set!"; exit; fi
