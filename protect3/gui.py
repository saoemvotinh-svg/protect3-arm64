"""GUI entrypoint routing to Qt Quick Studio (or legacy Tkinter fallback if PySide6 is absent)."""

import os


def launch():
    """Launch Qt Quick Studio when PySide6 is available, otherwise fall back to legacy Tkinter UI."""
    if os.environ.get("PROTECT3_UI", "").lower() != "tk":
        try:
            from .ui import launch as qt_launch
            qt_launch()
            return
        except ImportError:
            pass
    from .legacy_tk_gui import launch as tk_launch
    tk_launch()


def __getattr__(name):
    if name in ("Application", "TrollDecoysDialog"):
        from . import legacy_tk_gui
        return getattr(legacy_tk_gui, name)
    raise AttributeError(name)
