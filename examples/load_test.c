#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: load_test /path/libsample.so\n"); return 2; }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }
    int (*add)(int,int) = (int (*)(int,int))dlsym(handle, "sample_add");
    int (*jni)(void *,void *) = (int (*)(void *,void *))dlsym(handle, "JNI_OnLoad");
    int (*native)(void *,void *) = (int (*)(void *,void *))dlsym(handle, "Java_com_example_Sample_nativeValue");
    if (!add || !jni || !native) { fprintf(stderr, "missing exports\n"); return 4; }
    int sum = add(1,2), version = jni(0,0), value = native(0,0);
    int (*throw_test)(void) = (int (*)(void))dlsym(handle, "sample_throw");
    if (throw_test && throw_test() != 42) { fprintf(stderr, "C++ exception test failed\n"); return 6; }
    const char *(*secret)(void) = (const char *(*)(void))dlsym(handle, "sample_secret");
    if (secret && strcmp(secret(), "Protect3 fixture string for rodata encryption")) return 7;
    printf("sum=%d jni=0x%x native=%d\n", sum, version, value);
    dlclose(handle);
    return sum == 45 && version == 0x10006 && value == 42 ? 0 : 5;
}
