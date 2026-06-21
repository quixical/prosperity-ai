"""Part 1: the always-on desktop wallpaper (Linux / GNOME background-replacement).

Renders the theme folder's current picture, drifting it along the figure-8
micro-shift (1px/10s by default), and installs each rendered frame as the GNOME
desktop background - which is drawn BEHIND the icons. (On GNOME 46 / Mutter a live
GL client window has no z-slot between the compositor background and the desktop
icons, so we feed frames to the background instead; the GL render + micro-shift
math are identical to the Windows build.)

It shifts PIXELS, not pictures - EXCEPT that when a full figure-8 completes
(~hours at the default cadence) it advances to the NEXT picture in the folder,
sequentially, with a configurable fade. Zero interaction; the only clean stop is
the sentinel from `main.py --stop` (or a process kill). The user's original
background is restored on stop.

Motion is ~1px/10s, so the background is refreshed at a low cadence
(BG_UPDATE_SEC); successive frames are nearly identical, making the motion
visually continuous and the compositor's per-update fade imperceptible.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from core.config import Config
from core.geometry import compute_layout
from core.microshift import figure8_period, picture_schedule
from core.theme import load_theme
from platform_linux import autostart, idle, paths, wallpaper_host
from platform_linux.monitors import enumerate_virtual_desktop
from render.offscreen import OffscreenCanvas
from render.renderer import Renderer, build_placement

# How often the background frame is re-rendered + installed. At 1px/10s this is a
# ~0.2px step, imperceptible, while keeping file/gsettings churn low.
BG_UPDATE_SEC = 2.0
# Main loop tick: keeps stop/idle checks responsive between background updates.
TICK_SEC = 0.5
# How often config.json is re-read so settings-panel changes apply live.
CFG_RELOAD_SEC = 10.0


def _playlist(config: Config, images) -> int:
    """Starting index within `images` for config.wallpaper_image (0 = first)."""
    if not images or not config.wallpaper_image:
        return 0
    want = Path(config.wallpaper_image).name.lower()
    for i, img in enumerate(images):
        if Path(img.file).name.lower() == want:
            return i
    return 0


def _frame_dir() -> Path:
    """Where rendered frames are written. Prefer tmpfs (/dev/shm) to spare the disk."""
    for base in (Path("/dev/shm"), paths.app_state_dir()):
        try:
            d = base / "pixel-shield-frames"
            d.mkdir(parents=True, exist_ok=True)
            return d
        except OSError:
            continue
    d = paths.app_state_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_wallpaper(config: Config) -> int:
    if not wallpaper_host.acquire_single_instance():
        return 0

    cfg_path = paths.config_path()
    source = paths.source_dir(config.wallpaper_folder, config.theme, config.themes_path)
    images = load_theme(source).images
    idx = _playlist(config, images)
    if not images:
        wallpaper_host.release_single_instance()  # leave the real background alone
        return 0

    vd = enumerate_virtual_desktop()
    layout = compute_layout(vd, config.multimonitor_mode, config.bezel_width_px)
    original_background = wallpaper_host.get_current_wallpaper()

    stop_file = paths.wallpaper_stop_file()
    if stop_file.exists():
        try:
            stop_file.unlink()
        except OSError:
            pass

    canvas = OffscreenCanvas(vd.width, vd.height)
    renderer = Renderer(canvas.ctx)

    # Live-tunable parameters (refreshed by _reload from config.json).
    cadence = config.cadence_sec_per_px
    margin = config.overscan_margin_px
    fade_sec = config.wallpaper_fade_sec
    fig8_period = figure8_period(cadence, margin)
    ss_idle_ms = config.screensaver_idle_min * 60_000.0

    frame_dir = _frame_dir()
    frame_paths = [frame_dir / "frame_a.jpg", frame_dir / "frame_b.jpg"]
    frame_toggle = 0

    ss_cooldown = 0.0
    last_media_t = 0.0

    _wp_log = os.environ.get("OLED_WP_LOG")

    def _wlog(m: str) -> None:
        if _wp_log:
            try:
                with open(_wp_log, "a", encoding="utf-8") as f:
                    f.write(m + "\n")
            except OSError:
                pass

    _wlog(f"START cadence={cadence} margin={margin} fig8={fig8_period:.0f}s")

    # Lazy 2-slot cache of (texture, placement) keyed by picture index. Placements
    # depend on `margin`, so the cache is cleared when margin/folder changes.
    loaded: dict[int, tuple] = {}

    def _evict_all() -> None:
        for tex, _pl in loaded.values():
            tex.release()
        loaded.clear()

    def _get(i: int):
        if i not in loaded:
            from render.textures import load_image
            tex = load_image(canvas.ctx, images[i].file)
            pl = build_placement(layout.canvas_w, layout.canvas_h, margin,
                                 tex.width, tex.height, images[i].focal)
            loaded[i] = (tex, pl)
        return loaded[i]

    def _reload() -> None:
        """Re-read config.json and apply folder/timing changes without a restart."""
        nonlocal cadence, margin, fade_sec, fig8_period, ss_idle_ms, source, images, idx
        try:
            fresh = Config.load(cfg_path)
        except Exception:
            return
        ss_idle_ms = fresh.screensaver_idle_min * 60_000.0
        fade_sec = fresh.wallpaper_fade_sec
        if fresh.cadence_sec_per_px != cadence or fresh.overscan_margin_px != margin:
            cadence = fresh.cadence_sec_per_px
            margin = fresh.overscan_margin_px
            fig8_period = figure8_period(cadence, margin)
            _evict_all()  # placements depend on margin
        new_source = paths.source_dir(fresh.wallpaper_folder, fresh.theme, fresh.themes_path)
        if str(new_source) != str(source):
            source = new_source
            new_images = load_theme(source).images
            if new_images:                 # keep the old folder if the new one isn't ready
                _evict_all()
                images = new_images
                idx = _playlist(fresh, images)

    def _render_and_install(elapsed: float) -> None:
        nonlocal frame_toggle
        a_i, b_i, fade = picture_schedule(elapsed, fig8_period, fade_sec, len(images), idx)
        tex_a, pl_a = _get(a_i)
        tex_b, pl_b = (_get(b_i) if b_i is not None else (None, None))
        for k in [k for k in loaded if k != a_i and k != b_i]:
            loaded.pop(k)[0].release()

        canvas.use()
        renderer.render(layout, pl_a, tex_a, pl_b, tex_b, elapsed, fade,
                        cadence, margin, vd.width, vd.height)
        img = canvas.to_image()
        out = frame_paths[frame_toggle]
        frame_toggle ^= 1  # alternate filenames so the URI always changes
        img.save(out, "JPEG", quality=92)
        wallpaper_host.set_background_uri(str(out))

    start = time.monotonic()
    next_render = 0.0
    next_idle = 0.0
    next_cfg = CFG_RELOAD_SEC
    last_log = -99.0

    try:
        _render_and_install(0.0)         # first frame immediately (no black gap)
        next_render = BG_UPDATE_SEC

        while True:
            now = time.monotonic()
            elapsed = now - start
            if stop_file.exists():
                break

            if elapsed >= next_cfg:
                next_cfg = elapsed + CFG_RELOAD_SEC
                _reload()

            if elapsed >= next_idle:
                next_idle = elapsed + 1.0
                if ss_cooldown > 0.0:
                    ss_cooldown = max(0.0, ss_cooldown - 1.0)
                if idle.media_active():
                    last_media_t = elapsed
                media_idle_ms = (elapsed - last_media_t) * 1000.0
                idle_ms = min(idle.get_idle_ms(), media_idle_ms)
                ss_running = wallpaper_host.is_screensaver_running()
                if elapsed - last_log >= 5.0:
                    _wlog(f"t={elapsed:.0f} eff_idle={idle_ms:.0f} thresh={ss_idle_ms:.0f} "
                          f"ss={ss_running} cd={ss_cooldown:.0f}")
                    last_log = elapsed
                if ss_cooldown <= 0.0 and not ss_running and idle_ms >= ss_idle_ms:
                    _wlog(f"t={elapsed:.0f} LAUNCH screensaver")
                    autostart.launch_detached(["screensaver", "/s"])
                    ss_cooldown = 15.0

            if elapsed >= next_render:
                next_render = elapsed + BG_UPDATE_SEC
                try:
                    _render_and_install(elapsed)
                except Exception as e:
                    _wlog(f"t={elapsed:.0f} RENDER ERR {e!r}")

            time.sleep(TICK_SEC)
    finally:
        _evict_all()
        renderer.release()
        canvas.release()
        wallpaper_host.restore_wallpaper(original_background)
        for fp in frame_paths:
            try:
                fp.unlink()
            except OSError:
                pass
        try:
            if stop_file.exists():
                stop_file.unlink()
        except OSError:
            pass
        wallpaper_host.release_single_instance()
    return 0


def stop_wallpaper() -> int:
    """Signal a running wallpaper instance to exit cleanly."""
    sf = paths.wallpaper_stop_file()
    sf.parent.mkdir(parents=True, exist_ok=True)
    sf.write_text("stop", encoding="utf-8")
    return 0
