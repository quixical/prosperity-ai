"""The GL renderer: N scissored per-monitor viewports, GPU UV-scaling, cross-fade.

UV pipeline (per image, per frame)
----------------------------------
1. cover-fit the image onto the OVERSCANNED canvas target
   (canvas + 2*reserve, reserve = micro-shift required_overscan) -> UV_T.
2. micro-shift slides a canvas-sized window inside that overscan: window_offset.
   -> the canvas's visible UV rect (win_u0..win_v1), same for A and B so the two
   cross-fading images shift coherently.
3. each monitor samples its sub-fraction of the canvas (Layout.MonitorDraw.sub).

All scaling happens on the GPU via these UVs; the CPU never resizes pixels. v is
top-down throughout (matches texture upload + shaders).
"""

from __future__ import annotations

import sys
from array import array
from dataclasses import dataclass
from pathlib import Path

import moderngl

from core.geometry import CoverFit, Layout, cover_fit
from core.microshift import required_overscan, window_offset
from render.textures import GLImage


def _shader_dir() -> Path:
    """Locate the shaders folder in both dev and PyInstaller-frozen layouts."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "render" / "shaders"
    return Path(__file__).resolve().parent / "shaders"


_SHADER_DIR = _shader_dir()
# 6 vertices/quad * 6 floats (pos.xy, uvA.uv, uvB.uv)
_FLOATS_PER_QUAD = 6 * 6


@dataclass
class Placement:
    """How one image maps onto the overscanned canvas (computed when it goes live)."""

    fit: CoverFit
    target_w: float
    target_h: float

    @property
    def qualifies(self) -> bool:
        return self.fit.qualifies


def build_placement(
    canvas_w: int, canvas_h: int, margin_px: float, image_w: int, image_h: int,
    focal: tuple[float, float] = (0.5, 0.5),
) -> Placement:
    """Cover-fit an image (by pixel size) onto (canvas + 2*reserve).

    Takes dimensions, not a GLImage, so qualification can be tested from image
    headers (Pillow .size) without a full GPU upload.
    """
    reserve = required_overscan(margin_px)
    tw = canvas_w + 2.0 * reserve
    th = canvas_h + 2.0 * reserve
    fit = cover_fit(tw, th, image_w, image_h, focal)
    return Placement(fit=fit, target_w=tw, target_h=th)


class Renderer:
    def __init__(self, ctx: moderngl.Context) -> None:
        self.ctx = ctx
        vert = (_SHADER_DIR / "image.vert").read_text(encoding="utf-8")
        frag = (_SHADER_DIR / "crossfade.frag").read_text(encoding="utf-8")
        self.prog = ctx.program(vertex_shader=vert, fragment_shader=frag)
        self.prog["texA"].value = 0
        self.prog["texB"].value = 1
        # One reusable buffer/VAO for a single monitor quad, rewritten per monitor.
        self.vbo = ctx.buffer(reserve=_FLOATS_PER_QUAD * 4)
        self.vao = ctx.vertex_array(
            self.prog, [(self.vbo, "2f 2f 2f", "in_pos", "in_uvA", "in_uvB")]
        )

    # ---- UV math --------------------------------------------------------

    def _canvas_window_uv(
        self, pl: Placement, off_x: float, off_y: float, margin_px: float,
        canvas_w: int, canvas_h: int,
    ) -> tuple[float, float, float, float]:
        """The texture-UV rect (v top-down) that maps onto the FULL canvas [0,1]."""
        du = pl.fit.uv1[0] - pl.fit.uv0[0]
        dv = pl.fit.uv1[1] - pl.fit.uv0[1]
        # micro-shift window origin as a fraction of the overscanned target...
        fx0 = off_x / pl.target_w
        fy0 = off_y / pl.target_h
        # ...and the canvas window's size as a fraction of that target.
        fwin = canvas_w / pl.target_w
        hwin = canvas_h / pl.target_h
        u0 = pl.fit.uv0[0] + du * fx0
        v0 = pl.fit.uv0[1] + dv * fy0
        return (u0, v0, u0 + du * fwin, v0 + dv * hwin)

    # ---- frame ----------------------------------------------------------

    def render(
        self,
        layout: Layout,
        plA: Placement,
        texA: GLImage,
        plB: Placement | None,
        texB: GLImage | None,
        time: float,
        fade: float,
        cadence_sec_per_px: float,
        margin_px: float,
        win_w: int,
        win_h: int,
    ) -> None:
        """Draw one frame: clear black, then each monitor's scissored viewport.

        If plB/texB are None (no cross-fade in progress) image A is used for both
        slots and fade is forced to 0.
        """
        ctx = self.ctx
        ctx.scissor = None
        ctx.clear(0.0, 0.0, 0.0, 1.0)

        if plB is None or texB is None:
            plB, texB, fade = plA, texA, 0.0
        self.prog["fade"].value = float(fade)

        off_x, off_y = window_offset(time, cadence_sec_per_px, margin_px)
        winA = self._canvas_window_uv(plA, off_x, off_y, margin_px,
                                      layout.canvas_w, layout.canvas_h)
        winB = self._canvas_window_uv(plB, off_x, off_y, margin_px,
                                      layout.canvas_w, layout.canvas_h)

        texA.texture.use(location=0)
        texB.texture.use(location=1)

        for draw in layout.draws:
            self._draw_monitor(draw, winA, winB, win_w, win_h)

    def _draw_monitor(self, draw, winA, winB, win_w: int, win_h: int) -> None:
        sx, sy, sw, sh = draw.scissor
        su0, sv0, su1, sv1 = draw.sub

        # Slice each image's canvas-window UV by this monitor's canvas sub-fraction.
        def slice_uv(win):
            wu0, wv0, wu1, wv1 = win
            du, dv = wu1 - wu0, wv1 - wv0
            return (wu0 + du * su0, wv0 + dv * sv0,
                    wu0 + du * su1, wv0 + dv * sv1)

        au0, av0, au1, av1 = slice_uv(winA)
        bu0, bv0, bu1, bv1 = slice_uv(winB)

        # NDC corners of the monitor's screen rect (GL bottom-left pixels -> NDC).
        def ndc(px, py):
            return (2.0 * px / win_w - 1.0, 2.0 * py / win_h - 1.0)

        x_l, y_b = ndc(sx, sy)
        x_r, y_t = ndc(sx + sw, sy + sh)

        # Screen-top (larger NDC y) maps to UV-top (v0). Two triangles.
        # vertex: pos.x pos.y  uvA.u uvA.v  uvB.u uvB.v
        verts = array("f", [
            x_l, y_t, au0, av0, bu0, bv0,   # TL
            x_r, y_t, au1, av0, bu1, bv0,   # TR
            x_r, y_b, au1, av1, bu1, bv1,   # BR
            x_l, y_t, au0, av0, bu0, bv0,   # TL
            x_r, y_b, au1, av1, bu1, bv1,   # BR
            x_l, y_b, au0, av1, bu0, bv1,   # BL
        ])
        self.vbo.write(verts.tobytes())
        self.ctx.scissor = (sx, sy, sw, sh)
        self.vao.render(moderngl.TRIANGLES, vertices=6)

    def release(self) -> None:
        for obj in (self.vao, self.vbo, self.prog):
            try:
                obj.release()
            except Exception:
                pass
