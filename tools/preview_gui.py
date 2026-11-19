"""Developer preview and Qt Quick Studio smoke test."""

import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from protect3.ui import _configure_qt_dll_paths


def main():
    _configure_qt_dll_paths()
    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")

    from PySide6.QtCore import QUrl
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtQml import QQmlApplicationEngine
    import PySide6.QtQuick  # noqa: F401
    from protect3.ui.bridge import Protect3ViewModel

    source = ROOT / "build" / "fixtures" / "libsample.so"
    if not source.is_file():
        raise RuntimeError("Run the unit tests first to build the sample fixture.")

    app = QGuiApplication.instance() or QGuiApplication(sys.argv)
    vm = Protect3ViewModel()
    engine = QQmlApplicationEngine()
    qml_dir = ROOT / "protect3" / "ui" / "qml"
    engine.addImportPath(str(qml_dir))
    engine.rootContext().setContextProperty("vm", vm)
    engine.rootContext().setContextProperty("fnModel", vm.function_model)
    engine.rootContext().setContextProperty("decoyModel", vm.decoy_model)
    engine.rootContext().setContextProperty("capModel", vm.capabilities_model)

    warnings = []
    engine.warnings.connect(lambda errs: warnings.extend(e.toString() for e in errs))
    engine.load(QUrl.fromLocalFile(str(qml_dir / "Main.qml")))
    if not engine.rootObjects() or warnings:
        raise RuntimeError(f"QML failed to load cleanly: {warnings}")

    win = engine.rootObjects()[0]

    def wait_until(pred, timeout=20.0):
        deadline = time.monotonic() + timeout
        while not pred() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.02)

    with tempfile.TemporaryDirectory(prefix="protect3-qt-") as tmp:
        output = Path(tmp) / "libsample.protected.so"
        vm.sourcePath = str(source)
        vm.outputPath = str(output)
        vm.forceOverwrite = True
        vm.inspectLibrary(str(source))
        wait_until(lambda: not vm.busy and vm.hasElf)
        vm.runProtect()
        wait_until(lambda: not vm.busy and vm.hasVerifyResult)
        if vm.verifyResult.get("status") != "passed":
            raise RuntimeError(f"Protect/Verify failed: {vm.verifyResult}")
        wait_until(lambda: False, 0.2)
        out_img = ROOT / "build" / "gui-preview.png"
        out_img.parent.mkdir(parents=True, exist_ok=True)
        win.grabWindow().save(str(out_img))
    win.close()
    print(f"Qt Quick Studio smoke test passed; screenshot saved to {out_img}")


if __name__ == "__main__":
    main()
