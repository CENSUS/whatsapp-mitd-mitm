/* gcc openssl_session.c -I openssl-1.1.1f -I openssl-1.1.1f/include/ -Wall -O2 -o openssl_session -L openssl-1.1.1f/ -lcrypto -lssl */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/* The following is not portable. We directly include header files from the
 * OpenSSL source code directory.
 */
#include <ssl/ssl_local.h>

#define MAX_LINE_TOKENS 32
#define BUF_SIZE 8192

static void hexlify(unsigned char *buf, size_t buf_len)
{
    size_t i;

    for(i = 0; i < buf_len; i++)
        printf("%.2x", buf[i]);
    printf("\n");
}


static void unhexlify(const char *str, unsigned char *out_buf, size_t *out_buflenp)
{
    size_t i = 0, j = 0, str_len, out_buflen;
    unsigned char c;

    if(str == NULL || out_buf == NULL || out_buflenp == NULL)
        goto _ret;

    str_len = strlen(str);

    if(str_len < 2 || str_len % 2 != 0)
    {
        goto _ret;
    }

    out_buflen = *out_buflenp;

    while(i < out_buflen && j < str_len - 1)
    {
        c = str[j];

        if(c >= '0' && c <= '9')
            c -= '0';
        else if(c >= 'a' && c <= 'f')
            c = 10 + (c - 'a');
        else if(c >= 'A' && c <= 'F')
            c = 10 + (c - 'A');
        else
            goto _ret;

        out_buf[i] |= c << 4;

        c = str[j + 1];

        if(c >= '0' && c <= '9')
            c -= '0';
        else if(c >= 'a' && c <= 'f')
            c = 10 + (c - 'a');
        else if(c >= 'A' && c <= 'F')
            c = 10 + (c - 'A');
        else
            goto _ret;

        out_buf[i] |= c;

        i += 1;
        j += 2;
    }

_ret:
    *out_buflenp = i;
}


static const SSL_CIPHER *get_ssl_cipher_by_name(const char *name)
{
    SSL_CTX *ctx;
    STACK_OF(SSL_CIPHER) *ciphers;

    const SSL_CIPHER *cipher = NULL;

    if((ctx = SSL_CTX_new(TLS_method())) == NULL)
    {
        ERR_print_errors_fp(stderr);
        goto _ret;
    }

    ciphers = SSL_CTX_get_ciphers(ctx);

    while((cipher = sk_SSL_CIPHER_pop(ciphers)) != NULL)
    {
        if(strcmp(SSL_CIPHER_get_name(cipher), name) == 0)
            break;
    }

    sk_SSL_CIPHER_free(ciphers);

_ret:
    return cipher;
}


static void process_line(char *line, SSL_SESSION *session)
{
    char *tok[MAX_LINE_TOKENS];
    int i;
    const SSL_CIPHER *cipher;

    i = 0;

    tok[i] = strtok(line, " ");
    i += 1;

    while(i < MAX_LINE_TOKENS && (tok[i] = strtok(NULL, " ")) != NULL)
        i += 1;

    if(i < 2)
        goto _ret;

    if(strcmp(tok[0], "VERSION") == 0)
    {
        session->ssl_version = atoi(tok[1]);
        printf("Set SSL version %d\n", session->ssl_version);
    }
    else if(strcmp(tok[0], "SESSION_ID") == 0)
    {
        session->session_id_length = SSL_MAX_SSL_SESSION_ID_LENGTH;
        unhexlify(tok[1], session->session_id, &session->session_id_length);

        if(session->session_id_length == 0)
        {
            fprintf(stderr, "Failed to unhexlify session id\n");
            goto _ret;
        }

        printf("Set session id ");
        hexlify(session->session_id, session->session_id_length);
    }
    else if(strcmp(tok[0], "SESSION_CTX") == 0)
    {
        session->sid_ctx_length = SSL_MAX_SID_CTX_LENGTH;
        unhexlify(tok[1], session->sid_ctx, &session->sid_ctx_length);

        if(session->sid_ctx_length == 0)
        {
            fprintf(stderr, "Failed to unhexlify session ctx\n");
            goto _ret;
        }

        printf("Set session ctx ");
        hexlify(session->sid_ctx, session->sid_ctx_length);
    }
    else if(strcmp(tok[0], "MASTER_KEY") == 0)
    {
        session->master_key_length = TLS13_MAX_RESUMPTION_PSK_LENGTH;
        unhexlify(tok[1], session->master_key, &session->master_key_length);

        if(session->master_key_length == 0)
        {
            fprintf(stderr, "Failed to unhexlify master key\n");
            goto _ret;
        }

        printf("Set master key ");
        hexlify(session->master_key, session->master_key_length);
    }
    else if(strcmp(tok[0], "CIPHER") == 0)
    {
        if((cipher = get_ssl_cipher_by_name(tok[1])) == NULL)
        {
            fprintf(stderr, "Cipher %s not found\n", tok[1]);
            goto _ret;
        }

        session->cipher = cipher;
        session->cipher_id = SSL_CIPHER_get_id(cipher);
        printf("Set cipher %s, id %ld\n", SSL_CIPHER_get_name(cipher), session->cipher_id);
    }

    session->flags |= SSL_SESS_FLAG_EXTMS;
    session->verify_result = X509_V_OK;

#if 0
    else if(strcmp(tok[0], "CC") == 0)
    {
        int j;
        size_t len;
        unsigned char buf[BUF_SIZE], *bufp;
        X509 *x509;

        for(j = 1; j < i; j++)
        {
            len = sizeof(buf);

            unhexlify(tok[j], buf, &len);

            bufp = &buf[0];

            if((x509 = d2i_X509(NULL, (const unsigned char **)&bufp, len)) == NULL)
            {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Error parsing certificate at index %d\n", j);
                hexlify(buf, len);
            }
        }
    }
#endif

_ret:
    return;
}


int main(int argc, char *argv[])
{
    char buf[BUF_SIZE], *bufp;
    size_t len;
    SSL_SESSION *session;
    FILE *fp;

    int r = EXIT_FAILURE;

    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s FILENAME\n", argv[0]);
        goto _ret;
    }

    if((fp = fopen(argv[1], "w")) == NULL)
    {
        perror("fopen");
        goto _ret;
    }

    if((session = SSL_SESSION_new()) == NULL)
    {
        ERR_print_errors_fp(stderr);
        goto _close;
    }

    while(fgets(buf, sizeof(buf), stdin) != NULL)
    {
        len = strlen(buf);

        while(len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n'))
        {
            buf[len - 1] = 0;
            len -= 1;
        }

        process_line(buf, session);
    }


    if((len = i2d_SSL_SESSION(session, NULL)) == 0)
    {
        ERR_print_errors_fp(stderr);
        goto _free;
    }

    if(len > sizeof(buf))
    {
        fprintf(stderr, "Length of SSL_SESSION > %zu\n", sizeof(buf));
        goto _free;
    }

    bufp = &buf[0];
    if(i2d_SSL_SESSION(session, (unsigned char **)&bufp) != len)
    {
        ERR_print_errors_fp(stderr);
        goto _free;
    }

    if(fwrite(buf, 1, len, fp) != len)
    {
        perror("fwrite");
        goto _free;
    }

    r = EXIT_SUCCESS;

_free:
    SSL_SESSION_free(session);

_close:
    fclose(fp);

_ret:
    return r;
}

