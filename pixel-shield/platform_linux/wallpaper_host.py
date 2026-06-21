"""Wallpaper host helpers (Linux / GNOME): background install + single-instance.

On GNOME 46 / Mutter there is no z-order slot for a live client window between the
compositor's background and the desktop icons, so the wallpaper is delivered by
replacing the GNOME background with our GPU-rendered frame (see modes.wallpaper /
render.offscreen). This module installs/restores that background and provides the
single-instance locks shared with the screensaver.

This is the Linux sibling of platform_win.wallpaper_host (WorkerW + SPI wallpaper).
"""

from __future__ import annotations

import fcntl
import subprocess
from pathlib import Path

from platform_linux import paths

# Background gsettings keys captured/restored for parity with the Windows build.
_BG_KEYS = ("picture-uri", "picture-uri-dark", "picture-options", "primary-color")
_BG_SCHEMA = "org.gnome.desktop.background"

_wallpaper_lock = None
_screensaver_lock = None


# ---------------------------------------------------------------------------
# Background install + capture/restore (gsettings)
# ---------------------------------------------------------------------------

def set_background_uri(path: str) -> None:
    """Install `path` as the GNOME desktop background (drawn behind the icons).

    Sets light+dark URIs (so it shows regardless of theme) and a 1:1 fill. The
    caller alternates between two filenames each update so the URI always changes
    and Mutter actually reloads the image.
    """
    uri = f"file://{path}"
    for key, val in (("picture-uri", uri),
                     ("picture-uri-dark", uri),
                     ("picture-options", "spanned")):
        try:
            subprocess.run(["gsettings", "set", _BG_SCHEMA, key, val],
                           capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass


def get_current_wallpaper() -> str:
    """Snapshot the current background settings as a restorable string."""
    parts = []
    for key in _BG_KEYS:
        try:
            val = subprocess.run(["gsettings", "get", _BG_SCHEMA, key],
                                 capture_output=True, text=True, timeout=5).stdout.strip()
            parts.append(f"{key}={val}")
        except (OSError, subprocess.SubprocessError):
            pass
    return "\n".join(parts)


def restore_wallpaper(state: str) -> None:
    """Re-apply a snapshot from get_current_wallpaper (no-op on empty)."""
    if not state:
        return
    for line in state.splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        if not val:
            continue
        try:
            subprocess.run(["gsettings", "set", _BG_SCHEMA, key, val],
                           capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass


# ---------------------------------------------------------------------------
# Single-instance locks (flock on a state file)
# ---------------------------------------------------------------------------

def _lock_path(name: str) -> Path:
    p = paths.app_state_dir()
    p.mkdir(parents=True, exist_ok=True)
    return p / name


def _acquire(name: str):
    fd = open(_lock_path(name), "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError:
        fd.close()
        return None


def _probe(name: str) -> bool:
    """True if `name` is currently locked by another process (i.e. running)."""
    try:
        fd = open(_lock_path(name), "w")
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        fd.close()


def acquire_single_instance() -> bool:
    global _wallpaper_lock
    _wallpaper_lock = _acquire("wallpaper.lock")
    return _wallpaper_lock is not None


def release_single_instance() -> None:
    global _wallpaper_lock
    if _wallpaper_lock is not None:
        try:
            _wallpaper_lock.close()
        except Exception:
            pass
        _wallpaper_lock = None


def acquire_screensaver_instance() -> bool:
    global _screensaver_lock
    _screensaver_lock = _acquire("screensaver.lock")
    return _screensaver_lock is not None


def release_screensaver_instance() -> None:
    global _screensaver_lock
    if _screensaver_lock is not None:
        try:
            _screensaver_lock.close()
        except Exception:
            pass
        _screensaver_lock = None


def is_wallpaper_running() -> bool:
    return _probe("wallpaper.lock")


def is_screensaver_running() -> bool:
    return _probe("screensaver.lock")
