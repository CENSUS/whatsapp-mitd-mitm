#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <android/log.h>

#include "log.h"


void log(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    __android_log_vprint(ANDROID_LOG_INFO, TAG, fmt, va);
    va_end(va);
}

void log_error(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, TAG, fmt, va);
    va_end(va);
}

void log_perror(const char *s)
{
    log_error("%s: %s", s, strerror(errno));
}

