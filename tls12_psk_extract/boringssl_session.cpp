// g++ boringssl_session.c -I boringssl/ -I boringssl/include -Wall -O2 -std=c++11 -o boringssl_session boringssl/build/crypto/libcrypto.a boringssl/build/ssl/libssl.a
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/ssl.h>

#include <ssl/internal.h>

#ifndef OPENSSL_IS_BORINGSSL
#error OPENSSL_IS_BORINGSSL is not defined. Are you using BoringSSL?
#endif

#define BUF_SIZE 8192

int mmap_file(const char *filename, void **memp, size_t *sizep)
{
    struct stat st;
    void *mem;
    int fd, r = -1;

    if((fd = open(filename, O_RDONLY)) < 0)
    {
        perror("mmap_file: open");
        goto _ret;
    }

    if(fstat(fd, &st) != 0)
    {
        perror("mmap_file: fstat");
        goto _close;
    }

    if((mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("mmap_file: mmap");
        goto _close;
    }

    *memp = mem;
    *sizep = st.st_size;

    r = 0;

_close:
    close(fd);

_ret:
    return r;
}


static char *hexdump(uint8_t *p, size_t size)
{
    static char buf[BUF_SIZE], *bufp;
    size_t i;

    memset(buf, 0, sizeof(buf));

    bufp = &buf[0];
    for(i = 0; i < size; i++)
        bufp += snprintf(bufp, sizeof(buf) - strlen(buf), "%.2x", p[i]);

    return &buf[0];
}


int main(int argc, char *argv[])
{
    unsigned char *buf;
    size_t size;
    SSL_SESSION *session = NULL;

    int  r = EXIT_FAILURE;

    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s FILENAME\n", argv[0]);
        goto _ret;
    }

    if(mmap_file(argv[1], (void **)&buf, &size) != 0)
        goto _ret;

    if((session = d2i_SSL_SESSION(NULL, (const uint8_t **)&buf, size)) == NULL)
    {
        ERR_print_errors_fp(stderr);
        goto _ret;
    }

    printf("VERSION %d\n", session->ssl_version);
    printf("SESSION_ID %s\n", hexdump(session->session_id, session->session_id_length));
    printf("MASTER_KEY %s\n", hexdump(session->master_key, session->master_key_length));
    printf("SESSION_CTX %s\n", hexdump(session->sid_ctx, session->sid_ctx_length));
    printf("HANDSHAKE_HASH %s\n", hexdump(session->original_handshake_hash, session->original_handshake_hash_len));
    printf("CIPHER %s\n", SSL_CIPHER_get_name(session->cipher));

    /* We don't expect TLS v1.3 serialized sessions (WaTLS is used for that
     * purpose), so we don't expect `session->psk_identity' to be set.
     *
     * buf = reinterpret_cast<unsigned char *>(session->psk_identity.get());
     * if(buf != NULL) { ... }
     */

    r = EXIT_SUCCESS;

_ret:
    return r;
}

