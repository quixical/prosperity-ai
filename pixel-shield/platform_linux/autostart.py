"""Run-at-login for the wallpaper (XDG autostart), plus a detached launcher.

Autostart writes ~/.config/autostart/pixel-shield.desktop (per-user, no root).
`launch_detached` is used by the settings GUI and the idle-watch to (re)start the
wallpaper / screensaver as independent processes that outlive the launcher.

Mirrors platform_win.autostart (HKCU Run + CreateProcess) on the XDG stack.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from platform_linux import paths

DESKTOP_FILE_NAME = "pixel-shield.desktop"
APP_NAME = "Pixel Shield"


def _autostart_dir() -> Path:
    return paths.config_home() / "autostart"


def _desktop_path() -> Path:
    return _autostart_dir() / DESKTOP_FILE_NAME


def _main_script() -> str:
    # platform_linux/autostart.py -> project root /main.py
    return str(Path(__file__).resolve().parent.parent / "main.py")


def _installed_launcher() -> str | None:
    """The /usr/bin wrapper from the .deb (sets PYTHONPATH for the bundled libs)."""
    for p in ("/usr/bin/pixel-shield", "/usr/local/bin/pixel-shield"):
        if os.path.exists(p):
            return p
    return None


def launch_args() -> list[str]:
    """Argv that starts the wallpaper: installed wrapper, frozen exe, or source."""
    wrapper = _installed_launcher()
    if wrapper:
        return [wrapper]
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, _main_script()]


def _exec_command() -> str:
    """A shell-quotable Exec= line for the .desktop autostart entry."""
    import shlex

    return " ".join(shlex.quote(a) for a in launch_args())


# ---- run-at-login -----------------------------------------------------------

def install() -> str:
    """Register the wallpaper to start at login. Returns the .desktop Exec line."""
    d = _autostart_dir()
    d.mkdir(parents=True, exist_ok=True)
    exec_line = _exec_command()
    content = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        "Comment=OLED burn-in protection wallpaper\n"
        f"Exec={exec_line}\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        "X-GNOME-Autostart-Delay=3\n"
    )
    _desktop_path().write_text(content, encoding="utf-8")
    return exec_line


def uninstall() -> None:
    """Remove the run-at-login entry (no-op if absent)."""
    try:
        _desktop_path().unlink()
    except FileNotFoundError:
        pass


def is_installed() -> bool:
    return _desktop_path().is_file()


def set_enabled(enabled: bool) -> None:
    install() if enabled else uninstall()


# ---- launch now -------------------------------------------------------------

def launch_detached(extra_args: list[str] | None = None) -> None:
    """Start an independent process that outlives us.

    No extra args -> the wallpaper; e.g. ['screensaver', '/s'] -> the screensaver.
    Uses start_new_session so the child survives the launcher exiting, and scrubs
    PyInstaller bootloader vars so a frozen build can re-spawn itself cleanly.
    """
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("_MEI") or key.startswith("_PYI"):
            del env[key]
    subprocess.Popen(
        launch_args() + list(extra_args or []),
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(Path(_main_script()).parent),
        env=env,
        close_fds=True,
    )
