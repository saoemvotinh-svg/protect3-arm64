"""Evidence-based crash triage. Missing evidence is never called a clean result."""

import re


LINE = re.compile(r"^(?:\d{4}-)?\d\d-\d\d\s+\S+\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s?(.*)$")


def analyze_log(text, package, library="libMyLibName.so", pids=()):
    records = []
    target_pids = set(map(int, pids))
    for line in text.splitlines():
        match = LINE.match(line)
        if match:
            pid, tid, level, tag, message = match.groups()
            records.append(dict(pid=int(pid), tid=int(tid), level=level, tag=tag.strip(), message=message, raw=line))
            if re.search(r"Process:\s*"+re.escape(package)+r"(?:,|\s|$)", message):
                target_pids.add(int(pid))
            startup=re.search(r"Start proc\s+(\d+):"+re.escape(package)+r"(?:/|\s|$)",message)
            if startup:
                target_pids.add(int(startup.group(1)))
            native = re.search(r"pid:\s*(\d+).*>>>\s*"+re.escape(package)+r"\s*<<<", message)
            if native:
                target_pids.add(int(native.group(1)))
            signal = re.search(r"Fatal signal.*\(\s*"+re.escape(package[-15:])+r"\s*\)", message)
            if signal:
                target_pids.add(int(pid))
    relevant = [r for r in records if r["pid"] in target_pids
                or package in r["message"]
                or (r["tag"] in ("DEBUG", "crash_dump64", "tombstoned") and target_pids)]
    process_records = [r for r in records if r["pid"] in target_pids]
    findings = []
    failures = [r["raw"] for r in process_records if r["tag"] == "Protect3" and "event=fatal" in r["message"]]
    if failures:
        findings.append(dict(category="protect3_explicit_failure", confidence="direct_log_evidence", evidence=failures))
    java = [r for r in process_records if r["tag"] == "AndroidRuntime"]
    if any("FATAL EXCEPTION" in r["message"] for r in java):
        loader = any("UnsatisfiedLinkError" in r["message"] for r in java)
        findings.append(dict(category="library_load_failure" if loader else "java_exception",
                             confidence="exception_logged_cause_unproven",
                             evidence=[r["raw"] for r in java][:70]))
    # Native backtraces are logged by a separate DEBUG/crash_dump process.
    native_blocks = []
    current = []
    for r in records:
        if "*** *** ***" in r["message"]:
            if current:
                native_blocks.append(current)
            current = [r]
        elif current and r["tag"] in ("DEBUG", "crash_dump64", "crash_dump32"):
            current.append(r)
    if current:
        native_blocks.append(current)
    for block in native_blocks:
        if not any(package in r["message"] or any(re.search(r"pid:\s*"+str(pid)+r"\b", r["message"]) for pid in target_pids) for r in block):
            continue
        frames = [r["raw"] for r in block if re.search(r"#\d+\s+pc\s", r["message"])]
        has_library = any(library in frame for frame in frames)
        findings.append(dict(category="native_backtrace_includes_library" if has_library else "native_backtrace_other_or_unknown",
                             confidence="stack_evidence_not_root_cause",
                             evidence=[r["raw"] for r in block][:100]))
    return {"package": package, "library": library, "target_pids": sorted(target_pids),
            "findings": findings,
            "conclusion": "evidence_found_needs_correlation" if findings else "insufficient_evidence_no_crash_observed_in_supplied_log",
            "guard_events": [r["raw"] for r in process_records if r["tag"] == "Protect3"],
            "limits": "No attribution from app disappearance alone. Java/loader errors can have native causes; a library frame does not prove the protector caused the crash.",
            "relevant_lines": [r["raw"] for r in relevant]}
