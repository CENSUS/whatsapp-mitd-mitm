#include <stdio.h>
#include <stdlib.h>

#include <android/log.h>

#define TAG "CENSUS"

void __attribute__((constructor)) initialize(void)
{
    __android_log_print(ANDROID_LOG_INFO, TAG, "pwnd!");
}

