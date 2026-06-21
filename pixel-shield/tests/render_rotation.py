"""Offscreen check of the wallpaper picture-rotation (schedule + texture cache +
renderer) at a SHORTENED period, so the ~3h advance is observable in seconds.
Not a pytest test. Run: python tests/render_rotation.py"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image

from core.config import MODE_SPAN, Config
from core.geometry import Rect, VirtualDesktop, compute_layout
from core.microshift import picture_schedule
from core.theme import load_theme
from render.gl_window import KIND_OVERLAY, GLWindow
from render.renderer import Renderer, build_placement
from render.textures import load_image

OUT = Path(__file__).resolve().parent.parent / "preview_out"
P, F = 2.0, 1.0  # 2s "figure-8", 1s fade — compressed from ~2.9h / 3s


def avg(data, w, h):
    sx = sy = 0
    tot = [0, 0, 0]; n = 0
    for y in range(h // 2 - 30, h // 2 + 30):
        for x in range(w // 2 - 30, w // 2 + 30):
            i = (y * w + x) * 4
            tot[0] += data[i]; tot[1] += data[i+1]; tot[2] += data[i+2]; n += 1
    return tuple(round(c / n) for c in tot)


def main():
    OUT.mkdir(exist_ok=True)
    cfg = Config()
    theme = load_theme(Path(__file__).resolve().parent.parent / "themes" / "sample")
    print("pictures:", [Path(i.file).name for i in theme.images])
    n = len(theme.images)

    window = GLWindow(VirtualDesktop.from_monitors([Rect(0, 0, 64, 64)]), kind=KIND_OVERLAY)
    ctx = window.ctx
    renderer = Renderer(ctx)
    CW, CH = 2560, 1440
    layout = compute_layout(VirtualDesktop.from_monitors([Rect(0, 0, CW, CH)]), MODE_SPAN)
    fbo = ctx.framebuffer(color_attachments=[ctx.texture((CW, CH), 4)])

    cache = {}
    def get(i):
        if i not in cache:
            t = load_image(ctx, theme.images[i].file)
            pl = build_placement(CW, CH, cfg.overscan_margin_px, t.width, t.height, theme.images[i].focal)
            cache[i] = (t, pl)
        return cache[i]

    # Sample times: hold pic0, mid-fade 0->1, settled pic1, mid-fade 1->2, settled pic2.
    samples = [("hold_p0", 1.0), ("fade_0to1", P + F/2), ("settled_p1", P + F + 0.2),
               ("fade_1to2", 2*P + F/2), ("settled_p2", 2*P + F + 0.2)]
    for name, t in samples:
        a_i, b_i, fade = picture_schedule(t, P, F, n, 0)
        ta, pla = get(a_i)
        tb, plb = (get(b_i) if b_i is not None else (None, None))
        fbo.use()
        renderer.render(layout, pla, ta, plb, tb, t, fade,
                        cfg.cadence_sec_per_px, cfg.overscan_margin_px, CW, CH)
        data = fbo.read(components=4)
        print(f"t={t:5.2f} {name:12} from={a_i} to={b_i} fade={fade:.2f} centerRGB={avg(data, CW, CH)}")
        img = Image.frombytes("RGBA", (CW, CH), data).convert("RGB").transpose(Image.FLIP_TOP_BOTTOM)
        img.save(OUT / f"rot_{name}.png")

    renderer.release(); window.close()
    print("saved rot_*.png to", OUT)


if __name__ == "__main__":
    main()
