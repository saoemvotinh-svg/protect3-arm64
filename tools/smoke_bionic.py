"""Opt-in Bionic loader smoke test in an unprivileged, offline ARM64 container.

This tests real dlopen/dlsym/constructors, not Android framework/SELinux behavior.
Docker must already be running. The image is pinned to the tested digest.
"""

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from protect3.elf import ELF
from protect3.engine import Options, protect
from tests.fixtures import build_fixtures

IMAGE = "termux/termux-docker:aarch64@sha256:45aedb5a8c0a69fb21d43132c79e6ae4bcd9b4d857213453e98825878cc47d9a"


def main():
    source = build_fixtures()
    folder = source.parent
    cases = [("original", source, 0)]
    settings = {
        "guard": Options(),
        "stripped": Options(strip_symbols=True),
        "encrypted": Options(encrypt_text=True),
        "encrypted_stripped": Options(encrypt_text=True, strip_symbols=True),
        "heuristics_report": Options(hooks=True, root=True, emulator=True, report_only=True),
        "compat_guard": Options(compat_layout=True),
        "compat_encrypted": Options(compat_layout=True, encrypt_text=True),
        "rodata": Options(encrypt_rodata=True,diagnostics=True),
        "text_rodata": Options(encrypt_text=True,encrypt_rodata=True,diagnostics=True),
        "compat_text_rodata": Options(compat_layout=True,encrypt_text=True,encrypt_rodata=True,diagnostics=True),
        "function_jni": Options(encrypt_function="JNI_OnLoad",compat_layout=True,diagnostics=True),
        "multi_function_e01": Options(encrypt_functions="sample_add,JNI_OnLoad",auth_encryption=True,masked_key=True,diagnostics=True),
        "lazy_strings_e03": Options(encrypt_strings=True,compat_layout=True,diagnostics=True),
        "obfuscated_o01_o06": Options(obfuscate_functions="sample_add,Java_com_example_Sample_nativeValue",compat_layout=True,diagnostics=True),
        "flattened_o07": Options(flatten_functions="sample_add,JNI_OnLoad",compat_layout=True,diagnostics=True),
        "virtualized_o08_o09": Options(virtualize_functions="sample_add,JNI_OnLoad,Java_com_example_Sample_nativeValue",compat_layout=True,diagnostics=True),
        "on_demand_r07": Options(on_demand_functions="sample_add",auth_encryption=True,compat_layout=True,diagnostics=True),
        "jni_runtime_r01_r06": Options(obfuscate_jni=True,runtime_integrity=True,prologue_check=True,sign_manifest=True,guard_self_check=True,compat_layout=True,diagnostics=True),
        "profile_max": Options(profile="max",compat_layout=True,watermark="bionic-smoke-v03",diagnostics=True),
        "wrapped_e08": Options(wrap_elf=True),
    }
    for name, options in settings.items():
        target = folder / f"libsample.{name}.so"
        protect(source, target, options, force=True)
        cases.append((name, target, 0))
    for variant in ("standard", "cpp"):
        variant_source = folder / f"libsample.{variant}.so"
        cases.append((variant+"_original", variant_source, 0))
        for encrypt in (False, True):
            name = variant + ("_encrypted" if encrypt else "_guard")
            target = folder / f"libsample.{name}.so"
            protect(variant_source, target, Options(encrypt_text=encrypt), force=True)
            cases.append((name, target, 0))
        name = variant+"_compat_encrypted"
        target = folder/f"libsample.{name}.so"
        protect(variant_source, target, Options(encrypt_text=True, compat_layout=True), force=True)
        cases.append((name, target, 0))
        name=variant+"_compat_text_rodata"
        target=folder/f"libsample.{name}.so"
        protect(variant_source,target,Options(encrypt_text=True,encrypt_rodata=True,compat_layout=True,diagnostics=True),force=True)
        cases.append((name,target,0))
    for name in ("guard", "encrypted"):
        target = folder / f"libsample.{name}.tampered.so"
        data = bytearray((folder / f"libsample.{name}.so").read_bytes())
        text = ELF(data).section(".text")
        data[text.offset + 4] ^= 0x40
        target.write_bytes(data)
        cases.append((name+"_tampered", target, 175))
    results = []
    for name, target, expected in cases:
        result = subprocess.run([
            "docker", "run", "--rm", "--network", "none", "--platform", "linux/arm64",
            "--mount", f"type=bind,source={folder},target=/p3,readonly",
            "--entrypoint", "/p3/load_test", IMAGE, "/p3/" + target.name,
        ], capture_output=True, text=True, timeout=120)
        passed = result.returncode == expected
        item = {"case": name, "expected_exit": expected, "exit": result.returncode,
                "passed": passed, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
        results.append(item)
        print(json.dumps(item, ensure_ascii=False), flush=True)
    report = {"scope": "Bionic loader in ARM64 Termux Docker/QEMU; not a physical Android device or SELinux test",
              "image": IMAGE, "cases": results}
    (ROOT / "build" / "bionic-smoke.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
