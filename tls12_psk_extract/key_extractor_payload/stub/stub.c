/* JNI DEX loader a.k.a. JNI stub */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>

#include <pthread.h>

#include <android/log.h>
#include <jni.h>

#include "log.h"
#include "dex.h"
#include "stub.h"


/* Lookup a class by name, using the default class loader, and return its
 * reference in `*classp'.
 */
static int get_class(JNIEnv *env, const char *name, jclass *classp)
{
    jclass class;

    int r = FAILURE;

    /* Use default class loader to get a reference to the requested class. */
    class = (*env)->FindClass(env, name);

    if((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        goto _ret;
    }

    *classp = class;

    r = SUCCESS;

_ret:
    return r;
}


/* Like `get_class()' defined above, but uses the given class loader. */
static int get_class_from_class_loader(JNIEnv *env, jobject loader,
        const char *name, jclass *classp)
{
    jclass loader_class, class;
    jmethodID method;
    jstring str;

    int r = FAILURE;


    /* Call this loader's `findClass()' using reflection. */
    if((loader_class = (*env)->GetObjectClass(env, loader)) == NULL)
        goto _ret;

    method = (*env)->GetMethodID(env, loader_class, "findClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");

    if((*env)->ExceptionCheck(env))
        goto _del_class_ref;

    if((str = (*env)->NewStringUTF(env, name)) == NULL)
        goto _del_class_ref;

    if((*env)->ExceptionCheck(env))
        goto _del_class_ref;

    class = (*env)->CallObjectMethod(env, loader, method, str);

    if((*env)->ExceptionCheck(env))
        goto _del_str_ref;


    *classp = class;

    r = SUCCESS;


_del_str_ref:
    (*env)->DeleteLocalRef(env, str);

_del_class_ref:
    (*env)->DeleteLocalRef(env, loader_class);

_ret:
    if((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return r;
}


/* Lookup a class by name, using the default class loader, and then lookup a
 * method with the given name and signature. Return a reference to the class in
 * `*classp' and a reference to the method in `*methodp'.
 */
static int get_method(JNIEnv *env, const char *class_name,
        const char *method_name, const char *method_signature, char is_static,
        jclass *classp, jmethodID *methodp)
{
    jclass class;
    jmethodID method;

    int r = FAILURE;


    /* Get reference to requested class. */
    if(get_class(env, class_name, &class) != SUCCESS)
        goto _ret;


    /* Get reference to requested method. */
    if(is_static)
        method = (*env)->GetStaticMethodID(env, class, method_name, method_signature);
    else
        method = (*env)->GetMethodID(env, class, method_name, method_signature);

    if((*env)->ExceptionCheck(env))
    {
        (*env)->DeleteLocalRef(env, class);
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        goto _ret;
    }


    *methodp = method;
    *classp = class;

    r = SUCCESS;

_ret:
    return r;
}


/* Like `get_method()' defined above, but uses given class loader. */
static int get_method_from_class_loader(JNIEnv *env, jobject loader,
        const char *class_name, const char *method_name,
        const char *method_signature, char is_static, jclass *classp,
        jmethodID *methodp)
{
    jclass class;
    jmethodID method;

    int r = FAILURE;


    /* Get reference to requested class. */
    if(get_class_from_class_loader(env, loader, class_name, &class) != SUCCESS)
        goto _ret;


    /* Get reference to requested method. */
    if(is_static)
        method = (*env)->GetStaticMethodID(env, class, method_name, method_signature);
    else
        method = (*env)->GetMethodID(env, class, method_name, method_signature);

    if((*env)->ExceptionCheck(env))
    {
        (*env)->DeleteLocalRef(env, class);
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        goto _ret;
    }


    *classp = class;
    *methodp = method;

    r = SUCCESS;

_ret:
    return r;
}


/* Load Java classes from the given file (JAR, DEX or APK). A new class loader
 * instance is created and returned in `*loaderp'.
 */
static int load_java_classes(JNIEnv *env, const char *filename,
        jobject parent_loader, jobject *loaderp)
{
    jstring dirstr, filestr;
    jclass class;
    jmethodID method;
    jobject loader;

    int r = FAILURE;


    /* Resolve `PathClassLoader' constructor. */
    if(get_method(env, "dalvik/system/PathClassLoader", "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V", 0,
            &class, &method) != SUCCESS)
        goto _ret;


    /* Prepare required arguments and call the constructor. */
    dirstr = (*env)->NewStringUTF(env, dirname(filename));

    if((*env)->ExceptionCheck(env))
        goto _del_class;

    filestr = (*env)->NewStringUTF(env, filename);

    if((*env)->ExceptionCheck(env))
        goto _del_dirstr;

    loader = (*env)->NewObject(env, class, method, filestr, dirstr, parent_loader);

    if((*env)->ExceptionCheck(env))
        goto _del_filestr;


    *loaderp = loader;

    r = SUCCESS;


_del_filestr:
    (*env)->DeleteLocalRef(env, filestr);

_del_dirstr:
    (*env)->DeleteLocalRef(env, dirstr);

_del_class:
    (*env)->DeleteLocalRef(env, class);

_ret:
    if((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    return r;
}


/* Attach to a new JNI environment and return it in `*envp'. */
static int get_java_env(JavaVM *vm, JNIEnv **envp)
{
    JNIEnv *env;

    int r = FAILURE;

    if((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK)
        goto _ret;

    *envp = env;

    r = SUCCESS;

_ret:
    return r;
}


/* Main stub initialization routine. */
int init(JavaVM *vm)
{
    JNIEnv *env;
    jobject main_loader;
    jclass main_class;
    jmethodID main_method;

    size_t size = (size_t)&dex_end - (size_t)&dex_start;

    int fd, r = FAILURE;


    log("Getting JNI environment");

    if(get_java_env(vm, &env) != SUCCESS)
        goto _ret;


    log("Dropping %zu-byte DEX file", size);

    if((fd = open(CLASSES_DEX, O_WRONLY | O_CREAT | O_TRUNC, 0750)) < 0)
    {
        log_perror("open");
        goto _ret;
    }

    write(fd, &dex_start, size);
    close(fd);


    log("Loading custom Java classes");

    if(load_java_classes(env, CLASSES_DEX, NULL, &main_loader) != SUCCESS)
        goto _ret;


    log("Switching to Java environment");

    if(get_method_from_class_loader(env, main_loader, "Main", "main",
            "([Ljava/lang/String;)V", 1, &main_class, &main_method) != SUCCESS)
        goto _ret;

    if((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        goto _ret;
    }

    (*env)->CallStaticVoidMethod(env, main_class, main_method);

    r = SUCCESS;

_ret:
    return r;
}


static void *thread_init(void *vm)
{
    /* Wait for the application's main `ActivityThread' to be created. */
    log("Sleeping");
    sleep(5);

    log("Initializing");
    init((JavaVM *)vm);

    return NULL;
}


jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    pthread_t tid;

    if(pthread_create(&tid, NULL, thread_init, (void *)vm) != 0)
        log_perror("JNI_OnLoad: pthread_create");

    return JNI_VERSION_1_6;
}


/* These two are exported by the original "libvlc.so". Define them here, so that
 * "libwhatsapp.so" does not complain.
 */
void mtk_convert(void) {}

void qcom_convert(void) {}

