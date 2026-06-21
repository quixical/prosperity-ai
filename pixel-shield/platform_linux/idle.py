"""System activity probes for the screensaver idle trigger (X11 / GNOME).

* get_idle_ms       - time since the last keyboard/mouse input (XScreenSaver).
* is_fullscreen_busy - the active window is fullscreen (video / presentation / game).
* audio_active      - something is actively playing on a PipeWire/Pulse sink.
* screensaver_inhibited - a video player registered an idle inhibitor (D-Bus).
* media_active      - any of the above: media is keeping the screen "awake".

Mirrors platform_win.idle. Every probe FAILS SAFE (returns idle=0 / busy=False)
so a detection error can never wedge the screensaver. No root, light deps.
"""

from __future__ import annotations

import subprocess

from Xlib import X, display
from Xlib.ext import screensaver  # noqa: F401  (registers screensaver_query_info)

# ---------------------------------------------------------------------------
# Keyboard / mouse idle (XScreenSaver extension)
# ---------------------------------------------------------------------------

_display = None


def _disp():
    """A cached X display connection, reopened if it ever goes bad."""
    global _display
    if _display is None:
        _display = display.Display()
    return _display


def _reset_disp() -> None:
    global _display
    try:
        if _display is not None:
            _display.close()
    except Exception:
        pass
    _display = None


def get_idle_ms() -> int:
    """Milliseconds since the last real user input (0 on failure).

    0 is the fail-safe value: the idle-watch treats it as "just active", so a
    probe error never spuriously launches the screensaver.
    """
    try:
        d = _disp()
        info = d.screen().root.screensaver_query_info()
        return int(info.idle)
    except Exception:
        _reset_disp()
        return 0


# ---------------------------------------------------------------------------
# Fullscreen / presentation state (EWMH active window)
# ---------------------------------------------------------------------------

def is_fullscreen_busy() -> bool:
    """True if the currently-active window is in the _NET_WM_STATE_FULLSCREEN state."""
    try:
        d = _disp()
        root = d.screen().root
        na = d.intern_atom("_NET_ACTIVE_WINDOW")
        prop = root.get_full_property(na, X.AnyPropertyType)
        if not prop or not prop.value:
            return False
        wid = prop.value[0]
        if not wid:
            return False
        win = d.create_resource_object("window", wid)
        st = d.intern_atom("_NET_WM_STATE")
        fs = d.intern_atom("_NET_WM_STATE_FULLSCREEN")
        sp = win.get_full_property(st, X.AnyPropertyType)
        return bool(sp and fs in sp.value)
    except Exception:
        _reset_disp()
        return False


# ---------------------------------------------------------------------------
# Audio output (PipeWire / PulseAudio via pactl)
# ---------------------------------------------------------------------------

def audio_active() -> bool:
    """True if any sink-input is currently un-corked (i.e. actively playing).

    A paused player corks its stream, so "Corked: no" distinguishes real playback
    (video/music) from a player that's merely open. Fail-safe to False.
    """
    try:
        out = subprocess.run(
            ["pactl", "list", "sink-inputs"],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return any(
        line.strip().lower() == "corked: no"
        for line in out.splitlines()
    )


# ---------------------------------------------------------------------------
# Idle inhibitors (D-Bus) — what video players register so the screen stays awake
# ---------------------------------------------------------------------------

# org.gnome.SessionManager.IsInhibited flag bits: 8 = "inhibit session idle".
_INHIBIT_IDLE = 8


def screensaver_inhibited() -> bool:
    """True if an app holds a GNOME idle inhibitor (e.g. a video player). Fail-safe."""
    try:
        out = subprocess.run(
            ["gdbus", "call", "--session",
             "--dest", "org.gnome.SessionManager",
             "--object-path", "/org/gnome/SessionManager",
             "--method", "org.gnome.SessionManager.IsInhibited", str(_INHIBIT_IDLE)],
            capture_output=True, text=True, timeout=3,
        ).stdout
        return "true" in out.lower()
    except (OSError, subprocess.SubprocessError):
        return False


def media_active() -> bool:
    """True if a fullscreen app/video is on screen, audio is playing, or an idle
    inhibitor is held — any signal that the user is consuming media."""
    return is_fullscreen_busy() or audio_active() or screensaver_inhibited()
