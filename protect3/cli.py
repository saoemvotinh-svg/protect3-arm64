import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from . import __version__
from .arm64 import discover_functions
from .elf import ELF, ProtectionError
from .engine import Options, capabilities, protect, read_library, verify_file
from .planner import ROADMAP_CATALOG, build_protection_plan, evaluate_protection_benchmark
from .runtime import build_runtime


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        prog="protect3",
        description="Protect3: Android ARM64 .so -> .so protector with explicit capability & pass reporting.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("gui", help="Open the Vietnamese desktop interface")
    commands.add_parser("capabilities", help="Show actual support, maturity and limits as JSON")

    inspect = commands.add_parser("inspect", help="Read ELF/ABI/JNI and function discovery information without executing")
    inspect.add_argument("input", type=Path)
    inspect.add_argument("--functions", action="store_true", help="Include F01/A03 function boundary & sensitivity table")

    plan_cmd = commands.add_parser("plan", help="Preview F05 protection plan, A03 scores and active roadmap IDs")
    plan_cmd.add_argument("input", type=Path)
    plan_cmd.add_argument("--profile", default="balanced", choices=("compat", "balanced", "anti-analysis", "max"))

    bench = commands.add_parser("benchmark", help="Evaluate A04/A05/A06 static & simplifier metrics between original and protected .so")
    bench.add_argument("original", type=Path)
    bench.add_argument("protected", type=Path)

    build = commands.add_parser("build-runtime", help="Recompile native guard from source with Android NDK")
    build.add_argument("--ndk", type=Path)

    verify = commands.add_parser("verify", help="Verify output file hash, ELF structure and A08 watermark against its report")
    verify.add_argument("input", type=Path)
    verify.add_argument("--report", type=Path)

    analyze = commands.add_parser("analyze-log", help="Classify native guard/loader/Java crash evidence from an existing log")
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--package", required=True)
    analyze.add_argument("--library", default="libnative.so")
    analyze.add_argument("--pid", type=int, action="append", default=[], help="Known app PID; repeat if startup lines are absent")

    run = commands.add_parser("protect", help="Write protected ARM64 .so and a JSON report")
    run.add_argument("input", type=Path)
    run.add_argument("-o", "--output", type=Path, required=True)
    run.add_argument("--ndk", type=Path)
    run.add_argument("--force", action="store_true", help="Overwrite existing output/report; never the input")
    run.add_argument("--no-integrity", action="store_true", help="Disable load-time code hashing (encryption still requires it)")
    run.add_argument("--no-debugger", action="store_true", help="Disable TracerPid check")
    run.add_argument("--hooks", action="store_true", help="Enable mapping-name heuristics for Frida/Xposed at load")
    run.add_argument("--root", action="store_true", help="Enable root/Magisk/Zygisk indicator heuristics at load")
    run.add_argument("--emulator", action="store_true", help="Enable emulator indicator heuristics at load")
    run.add_argument("--encrypt-text", action="store_true", help="Encrypt all .text with ChaCha20")
    run.add_argument("--encrypt-function", default="", metavar="SYMBOL", help="Encrypt one named ARM64 STT_FUNC/FDE range")
    run.add_argument("--encrypt-functions", default="", metavar="LIST", help="Encrypt multiple comma-separated STT_FUNC/FDE ranges (E01)")
    run.add_argument("--encrypt-rodata", action="store_true", help="Encrypt .rodata + reloc-free unwind sections with ChaCha20 (E02)")
    run.add_argument("--encrypt-data", action="store_true", help="Sparse relocation-safe ChaCha20 encryption of RW .data strings/constants (E02+)")
    run.add_argument("--encrypt-strings", action="store_true", help="Per-reference lazy string encryption in page-isolated String Vault (E03)")
    run.add_argument("--auth-encryption", action="store_true", help="Verify pre-decryption HMAC-SHA256 tag over ciphertext and range context (E04)")
    run.add_argument("--sign-manifest", action="store_true", help="Sign and verify protection manifest inside native guard (E05)")
    run.add_argument("--clean-metadata", action="store_true", help="Scrub non-allocated .comment/debug metadata sections (E06)")
    run.add_argument("--keep-debug", default="", metavar="PATH", help="Save a copy of the unstripped input before stripping/cleaning (E06)")
    run.add_argument("--masked-key", action="store_true", help="Derive ChaCha20 master key at runtime via split-key HMAC KDF (E07)")
    run.add_argument("--wrap-elf", action="store_true", help="Package entire .so inside a standalone encrypted wrapper .so (E08)")
    run.add_argument("--pack-elf", action="store_true", help="Compress & ChaCha20 encrypt all PT_LOAD segments, relocs, and imports in-memory (E09)")
    run.add_argument("--obfuscate-ops", action="store_true", help="Enable ARM64 instruction substitution, opaque constants/predicates & block shuffling (O01-O06)")
    run.add_argument("--obfuscate-guard", action="store_true", help="Relocate and self-obfuscate native guard helpers with MBA/CFF/opaque/<unknown> islands (O10)")
    run.add_argument("--obfuscate-functions", default="", metavar="LIST", help="Relocate & obfuscate comma-separated functions in .guard (O01-O06)")
    run.add_argument("--flatten-cfg", action="store_true", help="Enable Control-Flow Flattening on selected functions (O07)")
    run.add_argument("--flatten-functions", default="", metavar="LIST", help="Flatten control flow of comma-separated functions (O07)")
    run.add_argument("--virtualize-functions", default="", metavar="LIST", help="Compile comma-separated ARM64 functions to polymorphic bytecode VM (O08/O09)")
    run.add_argument("--virtualize-auto", action="store_true", help="Automatically virtualize top-scoring VM-compatible functions (O08/O09)")
    run.add_argument("--obfuscate-jni", action="store_true", help="Obfuscate JNI_OnLoad and Java_* bodies behind runtime-checked guard thunks")
    run.add_argument("--runtime-integrity", action="store_true", help="Verify code/prologue/manifest integrity at runtime function gates (R01)")
    run.add_argument("--prologue-check", action="store_true", help="Verify exported/JNI function prologue bytes against inline hooks (R02)")
    run.add_argument("--got-check", action="store_true", help="Verify post-relocation GOT entries against module code bounds (R03)")
    run.add_argument("--relro-check", action="store_true", help="Verify static .data.rel.ro pointer table SHA-256 (R04)")
    run.add_argument("--runtime-anti-debug", action="store_true", help="Run TracerPid/wchan anti-debug checks at runtime function gates (R05)")
    run.add_argument("--guard-self-check", action="store_true", help="Verify native guard code SHA-256 at load and runtime gates (R06)")
    run.add_argument("--on-demand-functions", default="", metavar="LIST", help="Relocate comma-separated functions to isolated pages for decrypt-on-call / re-encrypt-on-return (R07)")
    run.add_argument("--deep-probes", action="store_true", help="Enable extended multi-signal Frida/Xposed/Zygisk/BlueStacks indicators when probes are active (R08)")
    run.add_argument("--gg-honeypot", action="store_true", help="Inject honeypot decoy page & verify canary memory against GameGuardian/RAM edits (R09)")
    run.add_argument("--ephemeral-strings", action="store_true", help="Auto re-encrypt String Vault entries shortly after access to minimize RAM exposure")
    run.add_argument("--anti-gg", action="store_true", help="Enable SIGSTOP freeze timing watchdog & GameGuardian scanner checks (R09)")
    run.add_argument("--profile", default="", choices=("", "compat", "balanced", "anti-analysis", "max"), help="Apply F05/A02 composite protection profile")
    run.add_argument("--auto-select-functions", action="store_true", help="Use A03 sensitivity/cost scorer to pick candidate functions")
    run.add_argument("--denylist-functions", default="", metavar="LIST", help="Comma-separated function names to exclude from transformations (F05)")
    run.add_argument("--seed", type=int, default=None, help="Deterministic structural diversification seed (A01)")
    run.add_argument("--watermark", default="", metavar="TAG", help="Embed verifiable offline build watermark into guard manifest (A08)")
    run.add_argument("--verify-semantics", action="store_true", help="Run Unicorn differential execution (F03) on transformed exports")
    run.add_argument("--diagnostics", action="store_true", help="Log native guard phases and check results to Android logcat and stderr")
    run.add_argument("--strip-symbols", action="store_true", help="Strip debug/nonessential symbols using NDK llvm-strip")
    run.add_argument("--compat-layout", action="store_true", help="Preserve original ELF header/dynamic table locations for native-bridge compatibility")
    run.add_argument("--strict-proc", action="store_true", help="Terminate if an enabled procfs check is unavailable")
    run.add_argument("--report-only", action="store_true", help="Log environment detections to stderr; integrity failures remain fatal")
    run.add_argument("--deny-attach", action="store_true", help="PR_SET_DUMPABLE=0 for the entire app process; affects crash reporting")
    run.add_argument("--troll-ida", action="store_true", help="Rename internal sub_XXXXXX functions to randomized barcode/troll names and inject F5 decoy functions")
    run.add_argument("--troll-barcode-chars", "--troll-chars", dest="troll_barcode_chars", default="IlO0", metavar="CHARS", help="Characters used to randomize barcode prefixes/names (default: IlO0)")
    run.add_argument("--troll-barcode-length", "--troll-length", dest="troll_barcode_length", type=int, default=17, metavar="N", help="Length of randomized barcode segment (0..128, default: 17)")
    run.add_argument("--troll-decoys", default="", metavar="SPEC", help="Custom troll function names & F5 strings (JSON, 'Name|Main|Alt' lines/semicolons, or @file path)")
    run.add_argument("--block-ida", action="store_true", help="Wipe static disassembler segments in IDA Pro via SHT_NOBITS+SHF_TLS while keeping Android Bionic intact")

    args = parser.parse_args(argv)
    try:
        if args.command in (None, "gui"):
            from .gui import launch
            launch()
            return 0
        if args.command == "capabilities":
            result = {
                "version": __version__,
                "target": "Android ARM64 only",
                "features": capabilities(),
                "roadmap_catalog": {
                    pid: {"kind": kind, "stage": stage, "summary": summary}
                    for pid, (kind, stage, summary) in ROADMAP_CATALOG.items()
                },
            }
        elif args.command == "inspect":
            elf = ELF(read_library(args.input))
            result = elf.summary()
            if args.functions:
                funcs = discover_functions(elf)
                result["function_discovery_F01"] = {
                    "total_functions": len(funcs),
                    "relocatable_count": sum(f.relocatable for f in funcs),
                    "vm_compatible_count": sum(f.vm_compatible for f in funcs),
                    "top_functions_A03": [
                        {
                            "name": f.name, "vaddr": hex(f.vaddr), "size": f.size,
                            "source": f.source, "relocatable": f.relocatable,
                            "vm_compatible": f.vm_compatible, "sensitivity_score": f.sensitivity_score,
                            "cost_score": f.cost_score,
                        }
                        for f in sorted(funcs, key=lambda x: (-x.sensitivity_score, x.cost_score))[:25]
                    ],
                }
        elif args.command == "plan":
            elf = ELF(read_library(args.input))
            plan = build_protection_plan(elf, Options(profile=args.profile))
            result = asdict(plan)
        elif args.command == "benchmark":
            orig = ELF(read_library(args.original))
            prot = ELF(read_library(args.protected))
            result = evaluate_protection_benchmark(orig, prot)
        elif args.command == "verify":
            result = verify_file(args.input, args.report)
        elif args.command == "build-runtime":
            _, result = build_runtime(args.ndk)
        elif args.command == "analyze-log":
            from .diagnostics import analyze_log
            result = analyze_log(args.input.read_text(encoding="utf-8", errors="replace"), args.package, args.library, args.pid)
        else:
            options = Options(
                integrity=not args.no_integrity,
                debugger=not args.no_debugger,
                **{key: getattr(args, key) for key in asdict(Options()) if key not in ("integrity", "debugger")},
            )
            result = protect(
                args.input, args.output, options, args.ndk, args.force,
                log=lambda message: print(message, file=sys.stderr, flush=True),
            )
            result.pop("details")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ProtectionError, OSError, ValueError) as exc:
        print(f"Protect3: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Protect3: cancelled.", file=sys.stderr)
        return 130
