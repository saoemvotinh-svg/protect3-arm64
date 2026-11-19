#include <stdexcept>
#include <string>

static std::string initialized("init");

extern "C" int sample_add(int a, int b) { return a + b + 38 + (int)initialized.size(); }
extern "C" int Java_com_example_Sample_nativeValue(void *, void *) { return 38 + (int)initialized.size(); }
extern "C" int JNI_OnLoad(void *, void *) { return 0x10006; }
extern "C" int sample_throw(void) {
    try { throw std::runtime_error("fixture"); }
    catch (const std::exception &) { return 42; }
}
