"""Read-only environment inventory and log capture; optional repeated app launches.

Never enable blocking environment checks or attach instrumentation to the app.
"""

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from protect3.diagnostics import analyze_log
from tools.trial_adb import Device


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial",required=True)
    parser.add_argument("--package",required=True)
    parser.add_argument("--library",default="libMyLibName.so")
    parser.add_argument("--launches",type=int,default=0)
    parser.add_argument("--seconds",type=int,default=20)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if not re.fullmatch(r"[\w]+(?:\.[\w]+)+",args.package) or not 0<=args.launches<=5 or not 5<=args.seconds<=60:
        parser.error("Invalid package or trial bounds (0..5 launches, 5..60 seconds).")
    device=Device(args.serial)
    stamp=datetime.now(timezone(timedelta(hours=7))).strftime("%Y%m%d-%H%M%S")
    folder=args.output or ROOT/"output"/("audit-"+stamp)
    folder.mkdir(parents=True,exist_ok=False)
    get=lambda cmd,root=False:device.shell(cmd,root=root,check=False)
    report={"schema":1,"serial":args.serial,"package":args.package,"time_local":stamp,
            "scope":"Read-only inventory; optional app restarts, no checks enabled, no instrumentation attached.","launches":[]}
    report["root_identity"]=get("id",True)
    report["properties"]={key:get("getprop "+key) for key in
         ("ro.build.version.release","ro.product.cpu.abilist","ro.hardware","ro.kernel.qemu",
          "ro.product.manufacturer","ro.product.model","ro.dalvik.vm.native.bridge")}
    ps=get("ps -A",True)
    report["indicator_processes"]=[line for line in ps.splitlines() if re.search(r"frida|xposed|lsposed|magisk|zygisk",line,re.I)]
    pkgs=get("pm list packages")
    report["indicator_packages"]=[line for line in pkgs.splitlines() if re.search(r"frida|xposed|lsposed|magisk",line,re.I)]
    paths=("/system/bin/su","/system/xbin/su","/sbin/su","/sbin/.magisk","/data/adb/magisk","/data/adb/ksu",
           "/dev/qemu_pipe","/dev/goldfish_pipe","/dev/socket/qemud")
    report["paths_visible_to_root"]={path:get("if test -e "+shlex.quote(path)+"; then echo visible; else echo absent_or_inaccessible; fi",True) for path in paths}
    report["app_uid"]=get("stat -c %u /data/data/"+args.package,True)
    uid=report["app_uid"]
    if uid.isdigit():
        report["paths_visible_to_app_uid_via_su"]={path:get("su "+uid+" -c "+shlex.quote("if test -e "+shlex.quote(path)+"; then echo visible; else echo absent_or_inaccessible; fi"),True) for path in paths}
        report["app_uid_probe_limit"]="UID matches app, but su probe does not guarantee the app's SELinux domain/mount namespace."
    def snapshot():
        pids=device.pid(args.package)
        mappings={str(pid):get("cat /proc/"+str(pid)+"/maps",True) for pid in pids}
        indicators={pid:[line for line in text.splitlines() if re.search(r"frida|gadget|xposed|lsposed|magisk|zygisk",line,re.I)] for pid,text in mappings.items()}
        return {"pids":pids,"indicator_mappings":indicators,
                "library_mappings":{pid:[line for line in text.splitlines() if args.library in line] for pid,text in mappings.items()}}
    report["initial_process"]=snapshot()
    apk=get("pm path "+args.package)
    report["package_paths"]=apk.splitlines()
    base=next((line[8:] for line in apk.splitlines() if line.endswith("/base.apk")),None)
    if base:
        installed=get("find "+shlex.quote(str(Path(base).parent).replace('\\','/')+"/lib")+" -name "+shlex.quote(args.library),True).splitlines()
        report["installed_libraries"]={p:get("sha256sum "+shlex.quote(p),True) for p in installed if p.startswith("/data/app/")}
    # Preserve available historical logs before starting any restart trials.
    history=device.adb("logcat","-d","-v","threadtime","-b","main","-b","system","-b","crash",check=False).stdout.decode(errors="replace")
    report["historical_analysis"]=analyze_log(history,args.package,args.library,report["initial_process"]["pids"])
    (folder/"historical-relevant.log").write_text("\n".join(report["historical_analysis"].pop("relevant_lines")),encoding="utf-8")
    if args.launches:
        activity=get("cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER "+args.package)
        component=next((line for line in activity.splitlines() if line.startswith(args.package+"/")),None)
        if not component:
            raise RuntimeError("Cannot resolve launcher activity.")
        for run in range(args.launches):
            since=get("date '+%m-%d %H:%M:%S.000'")
            get("am force-stop "+args.package)
            launch=get("am start -n "+shlex.quote(component))
            stream_path=folder/f".launch-{run+1}.tmp"
            with stream_path.open('wb') as stream_file:
                stream=subprocess.Popen(['adb','-s',args.serial,'logcat','-v','threadtime','-b','main','-b','system','-b','crash','-T',since],stdout=stream_file,stderr=subprocess.DEVNULL)
                try:
                    samples=[]; start=time.monotonic()
                    while True:
                        sample=snapshot();sample["elapsed"]=round(time.monotonic()-start,1);samples.append(sample)
                        print("launch",run+1,"elapsed",sample["elapsed"],"pids",sample["pids"],flush=True)
                        if sample["elapsed"]>=args.seconds:
                            break
                        time.sleep(min(5,args.seconds-sample["elapsed"]))
                finally:
                    stream.terminate()
                    try:
                        stream.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        stream.kill();stream.wait(timeout=5)
            logs=stream_path.read_text(encoding='utf-8',errors='replace')
            stream_path.unlink()
            pids={pid for sample in samples for pid in sample["pids"]}
            analysis=analyze_log(logs,args.package,args.library,pids)
            (folder/f"launch-{run+1}.log").write_text("\n".join(analysis.pop("relevant_lines")),encoding="utf-8")
            report["launches"].append({"start":since,"activity_result":launch,"samples":samples,"analysis":analysis})
            (folder/"audit.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    instrument_lines=report["indicator_processes"]+report["indicator_packages"]
    for sample in [report["initial_process"]]+[s for run in report["launches"] for s in run["samples"]]:
        instrument_lines += [line for lines in sample["indicator_mappings"].values() for line in lines]
    instrumentation=[line for line in instrument_lines if re.search(r"frida|gadget|xposed|lsposed",line,re.I)]
    report["frida_xposed_evidence"]=instrumentation
    report["interpretation"]={"root":"confirmed" if "uid=0(" in report["root_identity"] else "not_confirmed",
        "frida_xposed":"indicators_observed" if instrumentation else "no_indicators_in_sample_not_proof_of_absence",
        "emulator":"environment_context_confirms_BlueStacks; existing qemu/goldfish heuristic may miss it",
        "runtime_detection_verification":"inventory_only_not_a_positive_runtime_detector_test"}
    (folder/"audit.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps({"output":str(folder),"interpretation":report["interpretation"],"historical_findings":[f["category"] for f in report["historical_analysis"]["findings"]]},indent=2),flush=True)


if __name__=="__main__":
    main()
