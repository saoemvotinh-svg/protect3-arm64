"""User preferences & preset persistence stored in OS user config directory (never install dir)."""

import json
import os
from pathlib import Path


def user_data_dir():
    """Return writable per-user application data directory for settings and logs."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / "Protect3"
    return Path.home() / ".config" / "protect3"


def settings_path():
    return user_data_dir() / "settings.json"


def log_path():
    return user_data_dir() / "protect3-desktop.log"


DEFAULT_SETTINGS = {
    "ndk_path": "",
    "last_source": "",
    "last_output": "",
    "recent_sources": [],
    "reduced_motion": False,
    "sidebar_collapsed": False,
    "dark_mode": True,
    "font_scale": 1.0,
    "troll_barcode_chars": "IlO0",
    "troll_barcode_length": 17,
}


def load_settings():
    """Load persisted settings cleanly without failing on missing or corrupt JSON."""
    data = dict(DEFAULT_SETTINGS)
    path = settings_path()
    try:
        if path.is_file():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
    except Exception:
        pass
    if not data["ndk_path"]:
        env_ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT") or ""
        if env_ndk:
            data["ndk_path"] = env_ndk
        elif os.name == "nt":
            for candidate in (Path("D:/Android/ndk/android-ndk-r27d"), Path("C:/Android/ndk/android-ndk-r27d")):
                if candidate.is_dir():
                    data["ndk_path"] = str(candidate)
                    break
    return data


def save_settings(payload):
    """Persist user preferences safely into per-user AppData."""
    try:
        path = settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except Exception:
        pass
