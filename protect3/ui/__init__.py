"""Qt Quick + PySide6 application bootstrap with safe DLL search setup and per-user crash logging."""

import ctypes
import logging
import os
from pathlib import Path
import sys
import traceback

from .settings import log_path


def _configure_qt_dll_paths():
    """Ensure PySide6/Qt6 QML plugin DLLs resolve cleanly even on Windows Store Python or portable builds."""
    if os.name == "nt" and not getattr(sys, "frozen", False):
        try:
            import PySide6
            import shiboken6

            pyside_dir = Path(PySide6.__file__).resolve().parent
            shiboken_dir = Path(shiboken6.__file__).resolve().parent
            extra = [str(pyside_dir), str(shiboken_dir)]
            current_path = os.environ.get("PATH", "")
            os.environ["PATH"] = os.pathsep.join(extra + ([current_path] if current_path else []))
            for folder in extra:
                if Path(folder).is_dir():
                    os.add_dll_directory(folder)
        except Exception:
            pass


def _setup_logging():
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(path),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        encoding="utf-8",
    )


def _show_fatal_startup_error(title, text):
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)
            return
        except Exception:
            pass
    print(f"{title}: {text}", file=sys.stderr)


def launch():
    """Boot the Qt Quick Protect3 Studio desktop application."""
    _setup_logging()
    _configure_qt_dll_paths()

    os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")
    if os.environ.get("PROTECT3_SOFTWARE_RENDER") == "1":
        os.environ.setdefault("QT_QUICK_BACKEND", "software")

    try:
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QGuiApplication, QIcon
        from PySide6.QtQml import QQmlApplicationEngine

        from .. import __version__
        from .bridge import Protect3ViewModel
    except Exception as exc:
        logging.exception("Failed to initialize Qt Quick runtime")
        _show_fatal_startup_error(
            "Protect3 Startup Error",
            f"Không thể khởi chạy giao diện Qt Quick:\n{exc}\n\nChi tiết đã ghi vào:\n{log_path()}",
        )
        raise SystemExit(1) from exc

    app = QGuiApplication(sys.argv)
    app.setOrganizationName("Protect3")
    app.setApplicationName("Protect3")
    app.setApplicationVersion(__version__)

    base_dir = Path(__file__).resolve().parent
    assets_dir = base_dir.parent / "assets"
    icon_file = assets_dir / "protect3.ico"
    if icon_file.is_file():
        app.setWindowIcon(QIcon(str(icon_file)))

    vm = Protect3ViewModel()
    engine = QQmlApplicationEngine()
    qml_dir = base_dir / "qml"
    engine.addImportPath(str(qml_dir))
    engine.rootContext().setContextProperty("vm", vm)
    engine.rootContext().setContextProperty("fnModel", vm.function_model)
    engine.rootContext().setContextProperty("decoyModel", vm.decoy_model)
    engine.rootContext().setContextProperty("capModel", vm.capabilities_model)

    qml_warnings = []
    engine.warnings.connect(lambda errs: qml_warnings.extend(e.toString() for e in errs))
    engine.load(QUrl.fromLocalFile(str(qml_dir / "Main.qml")))

    if not engine.rootObjects():
        details = "\n".join(qml_warnings) or "No root QML object created."
        logging.error("QML load failed:\n%s", details)
        _show_fatal_startup_error("Protect3 QML Error", f"Không thể nạp giao diện:\n{details}")
        raise SystemExit(1)

    if qml_warnings:
        logging.warning("QML warnings:\n%s", "\n".join(qml_warnings))

    def _excepthook(etype, value, tb):
        msg = "".join(traceback.format_exception(etype, value, tb))
        logging.error("Unhandled exception:\n%s", msg)
        sys.__excepthook__(etype, value, tb)

    sys.excepthook = _excepthook
    exit_code = app.exec()
    raise SystemExit(exit_code)
