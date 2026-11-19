"""Backed-up rooted-device trial of a protected library in an installed package.

No APK repackaging, signing changes, data clearing, or SELinux changes. On a failed
trial restore exactly the native library that was installed before this run.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from protect3.elf import ELF
from protect3.engine import Options, protect, verify_file


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Device:
    def __init__(self, serial):
        self.serial = serial

    def adb(self, *args, timeout=45, check=True):
        result = subprocess.run(["adb", "-s", self.serial, *map(str, args)],
                                capture_output=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"ADB failed ({result.returncode}): " + result.stderr.decode(errors="replace"))
        return result

    def shell(self, command, root=False, check=True, timeout=45):
        if root:
            command = "su -c " + shlex.quote(command)
        result = self.adb("shell", command, check=check, timeout=timeout)
        return result.stdout.decode("utf-8", errors="replace").strip()

    def read_root(self, path):
        # Some emulator su brokers allocate a PTY and transform LF/CR bytes even
        # under exec-out. Use ADB's binary sync protocol for these readable libs.
        with tempfile.TemporaryDirectory(prefix="protect3-adb-read-") as temporary:
            destination = Path(temporary)/"library.bin"
            self.adb("pull", path, destination)
            return destination.read_bytes()

    def sha256(self, path):
        value = self.shell("sha256sum " + shlex.quote(str(path)), root=True).split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise RuntimeError("Cannot read on-device SHA-256.")
        return value

    def package_path(self, package):
        rows = self.shell("pm path " + shlex.quote(package)).splitlines()
        base = next((row[8:] for row in rows if row.startswith("package:") and row.endswith("/base.apk")), None)
        if not base or not base.startswith("/data/app/"):
            raise RuntimeError("Could not resolve the installed package base APK path.")
        return str(PurePosixPath(base).parent)

    def pid(self, package):
        result = self.shell("pidof " + shlex.quote(package), check=False)
        return [int(value) for value in result.split() if value.isdigit()]


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--observe", type=int, default=45)
    parser.add_argument("--baseline", type=int, default=15)
    parser.add_argument("--mode", choices=("encrypt", "guard", "plain"), default="encrypt",
                        help="plain/guard isolate source and ELF-loader compatibility during diagnosis")
    parser.add_argument("--compat-layout", action="store_true")
    parser.add_argument("--encrypt-rodata",action="store_true")
    parser.add_argument("--diagnostics",action="store_true")
    parser.add_argument("--auth-encryption",action="store_true")
    parser.add_argument("--sign-manifest",action="store_true")
    parser.add_argument("--masked-key",action="store_true")
    parser.add_argument("--guard-self-check",action="store_true")
    parser.add_argument("--prologue-check",action="store_true")
    parser.add_argument("--clean-metadata",action="store_true")
    parser.add_argument("--obfuscate-jni",action="store_true")
    parser.add_argument("--encrypt-strings",action="store_true")
    parser.add_argument("--obfuscate-ops",action="store_true")
    parser.add_argument("--flatten-cfg",action="store_true")
    parser.add_argument("--virtualize-auto",action="store_true")
    parser.add_argument("--runtime-integrity",action="store_true")
    parser.add_argument("--strip-symbols",action="store_true")
    parser.add_argument("--report-only",action="store_true")
    parser.add_argument("--strict-proc",action="store_true")
    parser.add_argument("--deny-attach",action="store_true")
    parser.add_argument("--root",action="store_true")
    parser.add_argument("--virtualize-functions",default="")
    parser.add_argument("--flatten-functions",default="")
    parser.add_argument("--obfuscate-functions",default="")
    parser.add_argument("--watermark",default="")
    parser.add_argument("--troll-ida",action="store_true")
    parser.add_argument("--block-ida",action="store_true")
    args = parser.parse_args()
    package, source = args.package, args.input.resolve()
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package):
        raise RuntimeError("Invalid Android package name.")
    if not re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.so", source.name):
        raise RuntimeError("Input basename must be a native library filename.")
    if not 5 <= args.observe <= 180 or not 5 <= args.baseline <= 60:
        raise RuntimeError("Observation/baseline duration outside supported bounds.")
    device = Device(args.serial)
    if "uid=0(" not in device.shell("id", root=True):
        raise RuntimeError("This trial requires an already rooted device.")
    package_root = device.package_path(package)
    candidates = device.shell("find " + shlex.quote(package_root+"/lib") + " -type f -name " + shlex.quote(source.name), root=True).splitlines()
    candidates = [value for value in candidates if value.startswith(package_root+"/lib/") and PurePosixPath(value).name == source.name]
    if len(candidates) != 1:
        raise RuntimeError(f"Expected exactly one installed {source.name}; found {len(candidates)}.")
    target = candidates[0]
    metadata = device.shell("stat -c '%a %u %g' " + shlex.quote(target), root=True).split()
    if len(metadata) != 3 or not all(value.isdigit() for value in metadata):
        raise RuntimeError("Could not capture original file mode/owner/group.")
    mode, owner, group = metadata
    labels = device.shell("ls -Zd " + shlex.quote(target), root=True)
    context = next((word for word in labels.split() if word.startswith("u:object_r:")), None)
    if not context or not re.fullmatch(r"[A-Za-z0-9_:,.-]+", context):
        raise RuntimeError("Could not capture the original SELinux file context.")
    activity_rows = device.shell("cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER " + shlex.quote(package)).splitlines()
    component = next((line for line in reversed(activity_rows) if line.startswith(package+"/") and " " not in line), None)
    if not component:
        raise RuntimeError("Could not resolve the package launcher activity.")
    stamp = datetime.now(timezone(timedelta(hours=7))).strftime("%Y%m%d-%H%M%S")
    token = uuid.uuid4().hex[:8]
    folder = ROOT / "output" / ("adb-"+package+"-"+stamp+"-"+token)
    folder.mkdir(parents=True, exist_ok=False)
    original_bytes = device.read_root(target)
    if digest(original_bytes) != device.sha256(target):
        raise RuntimeError("Installed library binary transfer failed checksum verification.")
    input_bytes = source.read_bytes()
    (folder/"device-original.so").write_bytes(original_bytes)
    (folder/"desktop-original.so").write_bytes(input_bytes)
    if len(original_bytes) < 64 or original_bytes[:4] != b"\x7fELF":
        raise RuntimeError("Installed target is not an ELF library; backup saved but replacement refused.")
    # A third-party protected/dumped library can have unusual section headers.
    # Preserve its exact bytes for rollback; only our Desktop input is rewritten.
    if args.mode != "plain":
        ELF(input_bytes).validate_target()
    elif ELF(input_bytes).machine != 183 or ELF(input_bytes).type != 3:
        raise RuntimeError("Plain diagnostic transfer still requires an ARM64 shared library.")
    output = folder / args.mode / source.name
    report = {"serial": args.serial, "package": package, "activity": component,
              "package_root": package_root, "target": target, "source": str(source),
              "mode": mode, "owner": owner, "group": group, "selinux_context": context,
              "device_original_sha256": digest(original_bytes), "desktop_original_sha256": digest(input_bytes),
              "baseline": [], "trial": [], "status": "backed_up", "folder": str(folder), "mode": args.mode}
    save_json(folder/"trial.json", report)
    print("EVIDENCE="+str(folder), flush=True)
    print("Backups saved; installed and Desktop libraries are preserved.", flush=True)
    if args.mode == "plain":
        output.parent.mkdir(parents=True)
        output.write_bytes(input_bytes)
    else:
        protect(source, output, Options(encrypt_text=args.mode == "encrypt", integrity=True, debugger=True,
                                       hooks=False, root=args.root, emulator=False, compat_layout=args.compat_layout,
                                       encrypt_rodata=args.encrypt_rodata, diagnostics=args.diagnostics,
                                       auth_encryption=args.auth_encryption, sign_manifest=args.sign_manifest,
                                       masked_key=args.masked_key, guard_self_check=args.guard_self_check,
                                       prologue_check=args.prologue_check, clean_metadata=args.clean_metadata,
                                       obfuscate_jni=args.obfuscate_jni, encrypt_strings=args.encrypt_strings,
                                       obfuscate_ops=args.obfuscate_ops, flatten_cfg=args.flatten_cfg,
                                       virtualize_auto=args.virtualize_auto, runtime_integrity=args.runtime_integrity,
                                       strip_symbols=args.strip_symbols, report_only=args.report_only,
                                       strict_proc=args.strict_proc, deny_attach=args.deny_attach,
                                       virtualize_functions=args.virtualize_functions,
                                       flatten_functions=args.flatten_functions,
                                       obfuscate_functions=args.obfuscate_functions,
                                       watermark=args.watermark,
                                       troll_ida=args.troll_ida,
                                       block_ida=args.block_ida), log=lambda text: print(text, flush=True))
        verify_file(output)
    encrypted_bytes = output.read_bytes()
    report["trial_sha256"] = digest(encrypted_bytes)
    remote_dir = "/data/local/tmp/protect3-trial-"+token
    remote_original = remote_dir+"/device-original.so"
    remote_encrypted = remote_dir+"/encrypted.so"
    stage = str(PurePosixPath(target).parent / (source.name+".protect3-stage-"+token))
    report.update(remote_backup=remote_original, remote_encrypted=remote_encrypted, stage=stage)
    device.shell("mkdir -p " + shlex.quote(remote_dir))
    device.adb("push", folder/"device-original.so", remote_original)
    device.adb("push", output, remote_encrypted)
    if device.sha256(remote_original) != digest(original_bytes) or device.sha256(remote_encrypted) != digest(encrypted_bytes):
        raise RuntimeError("Device staging checksums do not match.")
    report["log_start"] = device.shell("date '+%m-%d %H:%M:%S.000'")
    save_json(folder/"trial.json", report)
    # Stream while the app runs: a busy game's circular log buffer can overwrite
    # guard startup lines long before a final `logcat -d` snapshot.
    raw_log=folder/".streaming-logcat.tmp"
    stream_file=raw_log.open("wb")
    stream=subprocess.Popen(["adb","-s",args.serial,"logcat","-v","threadtime","-b","main","-b","system","-b","crash","-T",report["log_start"]],
                            stdout=stream_file,stderr=subprocess.DEVNULL)

    def launch():
        device.shell("am force-stop " + shlex.quote(package))
        result = device.shell("am start -n " + shlex.quote(component), timeout=20)
        if "Error:" in result or "Exception" in result:
            raise RuntimeError("Activity launch failed: "+result)
        print("Activity started.", flush=True)
        return result

    def observe(section, duration, require_maps=False):
        start = time.monotonic()
        samples = report[section]
        while True:
            elapsed = round(time.monotonic()-start, 1)
            pids = device.pid(package)
            mappings = {}
            for pid in pids:
                text = device.shell("grep -F " + shlex.quote(source.name) + " /proc/"+str(pid)+"/maps", root=True, check=False)
                if text:
                    mappings[str(pid)] = text.splitlines()
                crash = device.adb("logcat", "-d", "-b", "crash", "--pid="+str(pid), "-T", report["log_start"], check=False).stdout.decode(errors="replace")
                if "FATAL EXCEPTION" in crash:
                    (folder/(section+"-fatal.txt")).write_text(crash, encoding="utf-8")
                    raise RuntimeError(section+": fatal exception observed in the app process.")
            samples.append({"elapsed": elapsed, "pids": pids, "library_mappings": mappings})
            save_json(folder/"trial.json", report)
            print(f"{section}: {elapsed:.1f}s pid={','.join(map(str,pids)) or 'none'} mapped={bool(mappings)}", flush=True)
            if elapsed >= 5 and not pids:
                raise RuntimeError(section+": app process exited during observation.")
            if elapsed >= duration:
                if require_maps and not mappings:
                    raise RuntimeError("The requested library was not observed in the app process maps.")
                break
            time.sleep(min(5, max(0.1, duration-elapsed)))

    def install(remote_source, expected):
        if device.package_path(package) != package_root:
            raise RuntimeError("Installed package path changed during trial; refusing to modify a different install.")
        if not target.startswith(package_root+"/lib/") or PurePosixPath(target).name != source.name:
            raise RuntimeError("Replacement target escaped the selected package's native library path.")
        device.shell("am force-stop " + shlex.quote(package))
        # Every path is quoted, and the temporary destination stays beside this exact target.
        command = " && ".join([
            "cp -p " + shlex.quote(target) + " " + shlex.quote(stage),
            "cat " + shlex.quote(remote_source) + " > " + shlex.quote(stage),
            "chown " + owner+":"+group + " " + shlex.quote(stage),
            "chmod " + mode + " " + shlex.quote(stage),
            "chcon " + shlex.quote(context) + " " + shlex.quote(stage),
            "mv -f " + shlex.quote(stage) + " " + shlex.quote(target),
        ])
        device.shell(command, root=True)
        if digest(device.read_root(target)) != expected:
            raise RuntimeError("Installed library checksum mismatch.")

    def capture_logs(name):
        text=raw_log.read_text(encoding="utf-8",errors="replace")
        # Save relevant process/loader/crash lines only, without clearing the device log buffer.
        pids = {pid for sample in report["baseline"]+report["trial"] for pid in sample["pids"]}
        selected = []
        for line in text.splitlines():
            fields = line.split()
            pid_match = len(fields)>2 and fields[2].isdigit() and int(fields[2]) in pids
            if pid_match or any(word in line for word in (package,source.name,"Protect3:","Fatal signal","Tombstone written")):
                selected.append(line)
        (folder/name).write_text("\n".join(selected)+"\n",encoding="utf-8")

    replaced = False
    try:
        report["baseline_launch"] = launch()
        observe("baseline", args.baseline, require_maps=True)
        capture_logs("baseline-logcat.txt")
        report["status"] = "baseline_passed"
        save_json(folder/"trial.json", report)
        replaced = True
        install(remote_encrypted, digest(encrypted_bytes))
        report["status"] = "trial_installed"
        save_json(folder/"trial.json", report)
        report["trial_launch"] = launch()
        observe("trial", args.observe, require_maps=True)
        capture_logs("encrypted-logcat.txt")
        from protect3.diagnostics import analyze_log
        analysis=analyze_log((folder/"encrypted-logcat.txt").read_text(encoding="utf-8"),package,source.name,
                            [pid for sample in report["trial"] for pid in sample["pids"]])
        analysis.pop("relevant_lines",None)
        report["log_analysis"]=analysis
        if args.diagnostics and not any("event=guard_return" in line for line in analysis["guard_events"]):
            raise RuntimeError("Diagnostic guard_return event was not observed; cannot verify the requested runtime executed.")
        report["status"] = args.mode+"_running_observed"
        report["final_pids"] = device.pid(package)
        report["final_device_sha256"] = digest(device.read_root(target))
        save_json(folder/"trial.json", report)
        print("SUCCESS: "+args.mode+" library installed; app stayed alive and library was mapped.",flush=True)
        return 0
    except BaseException as exc:
        report["error"] = str(exc)
        try:
            capture_logs("failed-logcat.txt")
            from protect3.diagnostics import analyze_log
            report['log_analysis']=analyze_log((folder/'failed-logcat.txt').read_text(encoding='utf-8'),package,source.name,
                                              [pid for sample in report['trial'] for pid in sample['pids']])
            report['log_analysis'].pop('relevant_lines',None)
        except Exception as log_error:
            report["log_error"] = str(log_error)
        if replaced:
            try:
                install(remote_original,digest(original_bytes))
                report["status"] = "restored_original_after_failed_trial"
                report["restore_launch"] = launch()
                time.sleep(5)
                report["restored_pids"] = device.pid(package)
                print("Trial did not meet verification checks; the previously installed library was restored. See log_analysis for cause evidence.",flush=True)
            except Exception as restore_error:
                report["status"] = "restore_failed"
                report["restore_error"] = str(restore_error)
        else:
            report["status"] = "aborted_before_replacement"
        save_json(folder/"trial.json",report)
        raise
    finally:
        stream.terminate()
        try:
            stream.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stream.kill();stream.wait(timeout=5)
        stream_file.close()
        raw_log.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
