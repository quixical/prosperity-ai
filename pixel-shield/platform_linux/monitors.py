"""Enumerate physical monitors and build a core.geometry.VirtualDesktop (X11).

Isolated here so core.geometry stays pure and headless-testable. Negative
coordinates (a monitor left of / above the primary) are preserved. Mirrors
platform_win.monitors, which uses EnumDisplayMonitors.

Primary source is `xrandr --listmonitors`, whose output is stable and explicit
about the primary marker and per-monitor geometry; if that is unavailable we fall
back to a single screen sized from the X11 default screen.
"""

from __future__ import annotations

import re
import subprocess

from core.geometry import Rect, VirtualDesktop

# " 0: +*DP-2 3840/700x2160/390+0+0  DP-2"
#         ^prim   W   /mm  H  /mm + x  + y
_MON_RE = re.compile(
    r"^\s*\d+:\s+\+(?P<prim>\*?)\S*?(?P<name>[\w-]+)\s+"
    r"(?P<w>\d+)/\d+x(?P<h>\d+)/\d+(?P<x>[+-]\d+)(?P<y>[+-]\d+)"
)


def _from_xrandr() -> VirtualDesktop | None:
    try:
        out = subprocess.run(
            ["xrandr", "--listmonitors"],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None

    monitors: list[Rect] = []
    primary_index = 0
    for line in out.splitlines():
        m = _MON_RE.match(line)
        if not m:
            continue
        x, y = int(m["x"]), int(m["y"])
        w, h = int(m["w"]), int(m["h"])
        if w <= 0 or h <= 0:
            continue
        if m["prim"]:
            primary_index = len(monitors)
        monitors.append(Rect(left=x, top=y, right=x + w, bottom=y + h))

    if not monitors:
        return None
    return VirtualDesktop.from_monitors(monitors, primary_index)


def _from_xlib() -> VirtualDesktop:
    """Single-screen fallback using the X11 default screen dimensions."""
    from Xlib import display

    d = display.Display()
    try:
        screen = d.screen()
        w, h = screen.width_in_pixels, screen.height_in_pixels
    finally:
        d.close()
    return VirtualDesktop.from_monitors([Rect(0, 0, w, h)], 0)


def enumerate_virtual_desktop() -> VirtualDesktop:
    """Build the VirtualDesktop from the live X11 monitor layout."""
    vd = _from_xrandr()
    if vd is not None:
        return vd
    return _from_xlib()
