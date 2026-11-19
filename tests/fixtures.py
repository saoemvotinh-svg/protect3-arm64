from pathlib import Path

from protect3.runtime import PROJECT, command, ndk_tool


def build_fixtures():
    folder = PROJECT / "build" / "fixtures"
    folder.mkdir(parents=True, exist_ok=True)
    compiler = ndk_tool("clang")
    library = folder / "libsample.so"
    command([compiler, "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O1", "-g",
             "-nostdlib", "-Wl,--hash-style=both", "-Wl,--build-id=sha1",
             "-Wl,-z,max-page-size=16384", "-Wl,-soname,libsample.so", "-Wl,-init,original_init",
             str(PROJECT / "examples" / "sample.c"), "-o", str(library)])
    command([compiler, "--target=aarch64-linux-android23", "-O2", "-Wl,-z,max-page-size=16384",
             str(PROJECT / "examples" / "load_test.c"), "-ldl", "-o", str(folder / "load_test")])
    for variant in ("noinit", "standard"):
        flags = ["-nostdlib"] if variant == "noinit" else []
        command([compiler, "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O1", "-g",
                 "-DP3_NO_DT_INIT=1", "-Wl,-z,max-page-size=16384", "-Wl,--build-id=sha1", *flags,
                 str(PROJECT / "examples" / "sample.c"), "-o", str(folder / f"libsample.{variant}.so")])
    command([ndk_tool("clang++"), "--target=aarch64-linux-android23", "-shared", "-fPIC", "-O1",
             "-static-libstdc++", "-Wl,-z,max-page-size=16384", "-Wl,--pack-dyn-relocs=none",
             str(PROJECT / "examples" / "sample_cpp.cpp"), "-o", str(folder / "libsample.cpp.so")])
    return library
