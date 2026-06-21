# Pixel Shield (Linux)

OLED burn-in protection for Ubuntu / GNOME, ported from the Windows reference. Two
programs share one portable core:

1. **Wallpaper** (always-on) — drifts the desktop background along a slow, rotating
   figure-8 (~1px / 10s) so nothing etches the panel, advancing one picture per
   completed figure-8 (~2.9h at defaults).
2. **Screensaver** (idle-triggered) — fullscreen random slideshow with the same
   micro-shift drift. *(Part 2 — in progress.)*

## Architecture

```
core/            portable, headless-unit-tested: geometry, microshift, theme, shuffle, config
render/          moderngl + pygame; offscreen.py renders frames headless for the wallpaper
modes/           wallpaper / screensaver / config_dialog runners
platform_linux/  Linux glue: paths (XDG), monitors (XRandR), idle (XScreenSaver),
                 media detection (PipeWire/D-Bus), background install, favorites, autostart
tests/           headless unit tests (geometry, microshift cadence cap, shuffle, scan, ...)
```

`core/` is shared verbatim with the Windows build; only `platform_linux/` differs
from `platform_win/`.

## How the wallpaper draws behind icons (GNOME 46 / Mutter / X11)

On GNOME/Mutter there is **no z-order slot for a live client window between the
compositor background and the desktop icons** (verified empirically — a window above
the icon layer covers the icons; a window below it is occluded by Mutter's
background). So instead of hosting a live GL window, the wallpaper renders each
micro-shifted frame **offscreen on the GPU** (the render + micro-shift math are
identical to the Windows build) and installs it as the GNOME background, which *is*
drawn behind the icons. Because the motion is ~1px/10s, successive frames are nearly
identical, so the refresh is visually continuous and the compositor's per-update
fade is imperceptible. The user's original background is restored on stop.

## Run

```
python3 -m venv --system-site-packages .venv && . .venv/bin/activate
pip install rawpy python-xlib            # moderngl/pygame/Pillow may already be present
python main.py            # run the wallpaper
python main.py --stop     # stop it (restores your background)
python main.py --install  # run at login (XDG autostart)
python main.py --status
pytest                    # headless unit tests
```

Config: `~/.config/pixel-shield/config.json`.
