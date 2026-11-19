import unittest
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from protect3.diagnostics import analyze_log


class CrashTriageTests(unittest.TestCase):
    def test_activity_manager_start_correlates_successful_guard_pid(self):
        text='11-18 13:00:00.000 200 200 I ActivityManager: Start proc 100:test.app/u0a90 for activity test.app/.Main\n11-18 13:00:00.010 100 100 I Protect3: event=guard_return\n'
        report=analyze_log(text,'test.app')
        self.assertEqual([100],report['target_pids'])
        self.assertEqual(1,len(report['guard_events']))
    def test_cli_handles_unicode_android_log_under_legacy_windows_encoding(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'crash.log'
            path.write_text('11-18 13:00:00.000 100 100 E AndroidRuntime: Process: test.app, PID: 100\n'
                            '11-18 13:00:00.000 100 100 E AndroidRuntime: FATAL EXCEPTION: thông báo：\n',encoding='utf-8')
            environment=dict(os.environ);environment['PYTHONIOENCODING']='cp1252'
            result=subprocess.run([sys.executable,'-m','protect3','analyze-log',str(path),'--package','test.app'],capture_output=True,env=environment)
            self.assertEqual(0,result.returncode,result.stderr)
            report=json.loads(result.stdout.decode('utf-8'))
            self.assertEqual('java_exception',report['findings'][0]['category'])
    def test_explicit_guard_failure_differs_from_java_crash(self):
        text="11-18 13:00:00.000 100 100 I Protect3: event=fatal code=175\n"
        report=analyze_log(text,'test.app',pids=[100])
        self.assertEqual('protect3_explicit_failure',report['findings'][0]['category'])

    def test_loader_failure_is_not_called_protector_root_cause(self):
        text='\n'.join('11-18 13:00:00.000 100 100 E AndroidRuntime: '+s for s in
            ('FATAL EXCEPTION: main','Process: test.app, PID: 100','java.lang.UnsatisfiedLinkError: dlopen failed'))
        report=analyze_log(text,'test.app')
        self.assertEqual('library_load_failure',report['findings'][0]['category'])
        self.assertEqual('exception_logged_cause_unproven',report['findings'][0]['confidence'])

    def test_other_application_fatal_is_not_attributed_to_target(self):
        text='11-18 13:00:00.000 200 200 E AndroidRuntime: FATAL EXCEPTION: main\n11-18 13:00:00.000 200 200 E AndroidRuntime: Process: other.app, PID: 200'
        report=analyze_log(text,'test.app',pids=[100])
        self.assertEqual([],report['findings'])

    def test_missing_crash_log_never_proves_no_crash(self):
        report=analyze_log('','test.app')
        self.assertEqual('insufficient_evidence_no_crash_observed_in_supplied_log',report['conclusion'])

    def test_native_target_backtrace_checks_library_frame(self):
        text='\n'.join('11-18 13:00:00.000 200 200 F DEBUG: '+s for s in
            ('*** *** ***','pid: 100, tid: 101, name: worker >>> test.app <<<',
             '#00 pc 00001234 /data/app/test/lib/arm64/libMyLibName.so'))
        report=analyze_log(text,'test.app')
        self.assertEqual('native_backtrace_includes_library',report['findings'][0]['category'])
