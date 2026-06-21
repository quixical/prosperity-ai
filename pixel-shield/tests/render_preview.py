"""Render the real sample theme through the full pipeline into PNGs (offscreen).
Not a pytest test. Run: python tests/render_preview.py"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image

from core.config import MODE_SPAN, Config
from core.geometry import Rect, VirtualDesktop, compute_layout
from core.theme import load_theme
from render.gl_window import GLWindow
from render.player import ThemePlayer
from render.renderer import Renderer

OUT = Path(__file__).resolve().parent.parent / "preview_out"


def save(fbo, w, h, name):
    OUT.mkdir(exist_ok=True)
    img = Image.frombytes("RGBA", (w, h), fbo.read(components=4)).convert("RGB")
    img = img.transpose(Image.FLIP_TOP_BOTTOM)  # GL bottom-left -> image top-left
    p = OUT / name
    img.save(p)
    print("wrote", p)


def main():
    cfg = Config(image_duration_sec=3, crossfade_duration_sec=2, multimonitor_mode=MODE_SPAN)
    theme = load_theme(Path(__file__).resolve().parent.parent / "themes" / "sample")
    print("theme images:", [Path(i.file).name for i in theme.images])

    window = GLWindow(VirtualDesktop.from_monitors([Rect(0, 0, 64, 64)]), hide_cursor=False)
    ctx = window.ctx
    renderer = Renderer(ctx)

    CW, CH = 2560, 1440
    layout = compute_layout(VirtualDesktop.from_monitors([Rect(0, 0, CW, CH)]), MODE_SPAN)
    fbo = ctx.framebuffer(color_attachments=[ctx.texture((CW, CH), 4)])
    player = ThemePlayer(ctx, theme, layout, cfg)

    # Frame 1: first image, micro-shift at t=0.
    fbo.use()
    f = player.update(0.0)
    renderer.render(layout, f.plA, f.texA, f.plB, f.texB, 0.0, f.fade,
                    cfg.cadence_sec_per_px, cfg.overscan_margin_px, CW, CH)
    save(fbo, CW, CH, "01_first_image.png")

    # Frame 2: drive into the cross-fade between image 1 and 2.
    for _ in range(200):
        f = player.update(0.02)
        if f.fade > 0.4:
            break
    fbo.use()
    renderer.render(layout, f.plA, f.texA, f.plB, f.texB, 2.0, f.fade,
                    cfg.cadence_sec_per_px, cfg.overscan_margin_px, CW, CH)
    save(fbo, CW, CH, f"02_crossfade_{f.fade:.2f}.png")

    player.release(); renderer.release(); window.close()
    print("done")


if __name__ == "__main__":
    main()
