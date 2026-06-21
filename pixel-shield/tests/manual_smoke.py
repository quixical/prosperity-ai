"""Manual GL smoke harness (NOT a pytest test — needs a real GL context).

Renders the full pipeline (cover-fit + micro-shift + cross-fade + N scissored
viewports) into an OFFSCREEN framebuffer and reads pixels back, so it verifies
the AMD GL driver path AND the multi-monitor compositor without a second display.

Run:  python tests/manual_smoke.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import moderngl
from PIL import Image

from core.config import MODE_SPAN, Config
from core.geometry import Rect, VirtualDesktop, compute_layout
from core.theme import load_theme
from render.gl_window import GLWindow
from render.player import ThemePlayer
from render.renderer import Renderer


def _gradient(path: Path, w: int, h: int, axis: str, color: tuple[int, int, int]):
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            f = (x / w) if axis == "x" else (y / h)
            px[x, y] = tuple(int(c * (0.25 + 0.75 * f)) for c in color)
    img.save(path)


def _avg(data: bytes, w: int, h: int, cx: int, cy: int, r: int = 20):
    """Average RGB over a small box centered at (cx, cy) of an RGBA buffer."""
    tot = [0, 0, 0]
    n = 0
    for y in range(max(0, cy - r), min(h, cy + r)):
        for x in range(max(0, cx - r), min(w, cx + r)):
            i = (y * w + x) * 4
            tot[0] += data[i]; tot[1] += data[i + 1]; tot[2] += data[i + 2]
            n += 1
    return tuple(c / max(1, n) for c in tot)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="oled_smoke_"))
    _gradient(tmp / "01_red.png", 3840, 2160, "x", (255, 40, 40))
    _gradient(tmp / "02_blue.png", 3840, 2160, "y", (40, 40, 255))
    theme = load_theme(tmp)
    assert len(theme.images) == 2, theme.images

    cfg = Config(image_duration_sec=0.1, crossfade_duration_sec=1.0,
                 overscan_margin_px=70, multimonitor_mode=MODE_SPAN)

    # Tiny real window just to obtain a GL context; we render to our own FBO.
    window = GLWindow(VirtualDesktop.from_monitors([Rect(0, 0, 64, 64)]),
                      hide_cursor=False)
    ctx = window.ctx
    renderer = Renderer(ctx)
    print("GL_RENDERER:", ctx.info.get("GL_RENDERER"))
    print("GL_VERSION :", ctx.info.get("GL_VERSION"))

    ok = True

    # ---- Case 1: single monitor, cover + micro-shift ----
    CW, CH = 2560, 1440
    layout1 = compute_layout(VirtualDesktop.from_monitors([Rect(0, 0, CW, CH)]),
                             MODE_SPAN)
    fbo1 = ctx.framebuffer(color_attachments=[ctx.texture((CW, CH), 4)])
    player = ThemePlayer(ctx, theme, layout1, cfg)
    assert player.has_content and not player.letterbox

    fbo1.use()
    frame = player.update(0.0)
    renderer.render(layout1, frame.plA, frame.texA, frame.plB, frame.texB,
                    0.0, frame.fade, cfg.cadence_sec_per_px,
                    cfg.overscan_margin_px, CW, CH)
    data = fbo1.read(components=4)
    center = _avg(data, CW, CH, CW // 2, CH // 2)
    print("single-monitor center RGB:", tuple(round(c) for c in center))
    if not (center[0] > 30 and center[0] > center[2]):  # reddish, non-black
        print("  FAIL: expected non-black reddish center"); ok = False
    else:
        print("  PASS: cover render is non-black")

    # advance into the cross-fade and confirm blue contributes
    for _ in range(40):
        frame = player.update(0.02)
    fbo1.use()
    renderer.render(layout1, frame.plA, frame.texA, frame.plB, frame.texB,
                    1.0, frame.fade, cfg.cadence_sec_per_px,
                    cfg.overscan_margin_px, CW, CH)
    data = fbo1.read(components=4)
    center = _avg(data, CW, CH, CW // 2, CH // 2)
    print("mid/late cross-fade center RGB:", tuple(round(c) for c in center),
          "fade=", round(frame.fade, 2))
    if frame.fade > 0 and center[2] <= 30:
        print("  FAIL: blue image not blending in"); ok = False
    else:
        print("  PASS: cross-fade blends")
    player.release()

    # ---- Case 2: two monitors side-by-side (negative origin) on the GPU ----
    left = Rect(-2560, 0, 0, 1440)
    right = Rect(0, 0, 2560, 1440)
    vd2 = VirtualDesktop.from_monitors([left, right], primary_index=1)
    layout2 = compute_layout(vd2, MODE_SPAN)
    W2, H2 = vd2.width, vd2.height  # 5120 x 1440
    fbo2 = ctx.framebuffer(color_attachments=[ctx.texture((W2, H2), 4)])
    player2 = ThemePlayer(ctx, theme, layout2, cfg)
    fbo2.use()
    frame = player2.update(0.0)
    renderer.render(layout2, frame.plA, frame.texA, frame.plB, frame.texB,
                    0.0, frame.fade, cfg.cadence_sec_per_px,
                    cfg.overscan_margin_px, W2, H2)
    data2 = fbo2.read(components=4)
    left_avg = _avg(data2, W2, H2, W2 // 4, H2 // 2)
    right_avg = _avg(data2, W2, H2, 3 * W2 // 4, H2 // 2)
    print("two-monitor LEFT avg :", tuple(round(c) for c in left_avg))
    print("two-monitor RIGHT avg:", tuple(round(c) for c in right_avg))
    # Horizontal red gradient: right half should be brighter red than left half.
    if left_avg[0] > 20 and right_avg[0] > left_avg[0]:
        print("  PASS: both viewports drawn, span gradient continuous L->R")
    else:
        print("  FAIL: span across two monitors incorrect"); ok = False
    player2.release()

    renderer.release()
    window.close()
    print("\nSMOKE", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
