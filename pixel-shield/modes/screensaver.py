"""Part 2: the idle-triggered screensaver.

Fullscreen overlay (covers taskbar + every window) showing a RANDOM slideshow from
the screensaver folder, with a minimal cross-fade and the same micro-shift drift so
even the screensaver doesn't etch the panel. Exits on ANY input after a short grace
period — EXCEPT Space, which favorites the current picture and keeps the show running
(this is why favoriting never worked before: Space used to quit the screensaver).
"""

from __future__ import annotations

import math
import os

import pygame

from core.config import Config
from core.geometry import compute_layout
from core.shuffle import ShuffleBag
from core.theme import load_theme
from platform_linux import favorites, paths, wallpaper_host
from platform_linux.monitors import enumerate_virtual_desktop
from render.gl_window import KIND_OVERLAY, GLWindow
from render.renderer import Renderer, build_placement
from render.textures import load_image

STARTUP_GRACE_SEC = 1.0
MOUSE_EXIT_THRESHOLD = 8.0

_HOLD = "hold"
_FADE = "fade"


def run_screensaver(config: Config) -> int:
    # One screensaver at a time (the idle-watcher may fire more than once).
    if not wallpaper_host.acquire_screensaver_instance():
        return 0

    source = paths.source_dir(config.screensaver_folder, config.theme, config.themes_path)
    theme = load_theme(source)
    images = theme.images
    if not images:
        wallpaper_host.release_screensaver_instance()
        return 0

    vd = enumerate_virtual_desktop()
    layout = compute_layout(vd, config.multimonitor_mode, config.bezel_width_px)
    margin = config.overscan_margin_px

    window = GLWindow(vd, kind=KIND_OVERLAY)
    renderer = Renderer(window.ctx)

    cache: dict[int, tuple] = {}

    def get(i: int):
        if i not in cache:
            t = load_image(window.ctx, images[i].file)
            pl = build_placement(layout.canvas_w, layout.canvas_h, margin,
                                 t.width, t.height, images[i].focal)
            cache[i] = (t, pl)
        return cache[i]

    bag = ShuffleBag(len(images))           # entropy-seeded: random start + order
    cur = bag.next()
    nxt: int | None = None
    phase = _HOLD
    phase_t = 0.0
    hold = config.image_duration_sec
    fade_dur = config.crossfade_duration_sec

    # Optional diagnostic logging (set OLED_SS_LOG=1).
    _logf = os.environ.get("OLED_SS_LOG")

    def _log(msg: str) -> None:
        if _logf:
            try:
                with open(_logf, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except OSError:
                pass

    _log(f"START images={len(images)} source={source}")

    clock = pygame.time.Clock()
    elapsed = 0.0
    mouse_travel = 0.0
    running = True
    try:
        while running:
            dt = clock.tick(60) / 1000.0
            elapsed += dt
            phase_t += dt
            past_grace = elapsed >= STARTUP_GRACE_SEC

            for event in pygame.event.get():
                if event.type in (pygame.KEYDOWN, pygame.MOUSEBUTTONDOWN, pygame.QUIT):
                    _log(f"t={elapsed:.1f} grace={past_grace} "
                         f"{pygame.event.event_name(event.type)} "
                         f"key={getattr(event, 'key', None)}")
                if event.type == pygame.QUIT:
                    running = False
                elif not past_grace:
                    continue                 # swallow whatever happened at launch
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_SPACE:
                        fav = favorites.favorite(
                            images[cur].file,
                            paths.favorites_dir(config.favorites_folder),
                        )   # keep running
                        _log(f"  FAVORITE cur={cur} -> {fav}")
                    else:
                        _log(f"  EXIT on key {event.key}")
                        running = False
                elif event.type == pygame.MOUSEBUTTONDOWN:
                    running = False
                elif event.type == pygame.MOUSEMOTION:
                    rx, ry = event.rel
                    mouse_travel += math.hypot(rx, ry)
                    if mouse_travel >= MOUSE_EXIT_THRESHOLD:
                        _log(f"  EXIT on mouse travel {mouse_travel:.1f}")
                        running = False

            # Random slideshow advance with a minimal fade.
            if phase == _HOLD and len(images) > 1 and phase_t >= hold:
                nxt = bag.next()
                get(nxt)                     # preload before the fade
                phase = _FADE
                phase_t = 0.0
            elif phase == _FADE and (phase_t >= fade_dur or fade_dur <= 0):
                cur, nxt = nxt, None
                phase = _HOLD
                phase_t = 0.0

            fade = min(1.0, phase_t / fade_dur) if (phase == _FADE and fade_dur > 0) else 0.0

            tex_a, pl_a = get(cur)
            tex_b, pl_b = get(nxt) if nxt is not None else (None, None)
            for k in [k for k in cache if k != cur and k != nxt]:
                cache.pop(k)[0].release()

            renderer.render(layout, pl_a, tex_a, pl_b, tex_b, elapsed, fade,
                            config.cadence_sec_per_px, margin, vd.width, vd.height)
            window.swap()
    finally:
        for tex, _pl in cache.values():
            tex.release()
        renderer.release()
        window.close()
        wallpaper_host.release_screensaver_instance()
    return 0
