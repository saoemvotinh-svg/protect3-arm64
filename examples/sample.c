/* Self-contained fixture, not an application to protect. */
static volatile int initialized;
static volatile int seen_argc;
static const char fixture_secret[]="Protect3 fixture string for rodata encryption";
const char *sample_secret(void) { return fixture_secret; }

void original_init(int argc, char **argv, char **envp) {
    (void)argv; (void)envp;
    initialized = 40;
    seen_argc = argc;
}

__attribute__((constructor)) static void sample_constructor(void) {
#ifdef P3_NO_DT_INIT
    initialized = 40;
#endif
    initialized += 2;
}

int sample_add(int a, int b) { return a + b + initialized; }
int sample_init_argc(void) { return seen_argc; }
int Java_com_example_Sample_nativeValue(void *env, void *object) {
    (void)env; (void)object;
    return initialized;
}
int JNI_OnLoad(void *vm, void *reserved) {
    (void)vm; (void)reserved;
    return 0x00010006;
}
