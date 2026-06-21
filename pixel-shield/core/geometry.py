"""Monitor / viewport geometry for the compositor.

PORTABLE: pure math, stdlib only. No win32/pygame/GL imports. This is the module
that the single-monitor dev box CANNOT exercise at runtime, so it is written to be
fully headless-testable (see tests/test_geometry.py): multi-monitor tiling,
negative virtual-desktop origins, Span vs Primary, and bezel correction.

Coordinate systems
------------------
* Win32 virtual-desktop space: origin top-left, +y DOWN. Monitors are Rects here
  and MAY have negative coordinates (e.g. a monitor left of the primary).
* GL window space: the borderless window covers the whole virtual desktop. GL
  scissor/viewport use origin bottom-left, +y UP. `to_gl_scissor` converts.
* Canvas space: the rectangle the *image* is mapped onto. For Span it is the whole
  virtual-desktop bounding box (optionally widened by bezel gaps); for Primary it
  is just the primary monitor. Each participating monitor samples a sub-rectangle
  of the canvas, expressed as fractions in [0,1] (`sub` on MonitorDraw).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import MODE_PRIMARY, MODE_SPAN


@dataclass(frozen=True)
class Rect:
    """Inclusive-left/top, exclusive-right/bottom, in virtual-desktop pixels."""

    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top


@dataclass(frozen=True)
class VirtualDesktop:
    """The full multi-monitor virtual desktop and its monitors."""

    origin_x: int
    origin_y: int
    width: int
    height: int
    monitors: tuple[Rect, ...]
    primary_index: int = 0

    @classmethod
    def from_monitors(
        cls, monitors: list[Rect], primary_index: int = 0
    ) -> "VirtualDesktop":
        """Derive the bounding box from monitor rects (origin-agnostic)."""
        if not monitors:
            raise ValueError("at least one monitor is required")
        left = min(m.left for m in monitors)
        top = min(m.top for m in monitors)
        right = max(m.right for m in monitors)
        bottom = max(m.bottom for m in monitors)
        return cls(
            origin_x=left,
            origin_y=top,
            width=right - left,
            height=bottom - top,
            monitors=tuple(monitors),
            primary_index=primary_index,
        )


@dataclass(frozen=True)
class MonitorDraw:
    """One monitor's draw instruction.

    scissor: (x, y, w, h) in GL bottom-left window space.
    sub:     (u0, v0, u1, v1) fraction of the *canvas* this monitor shows, with
             v measured top-down to match image/texture orientation (v0 = top).
    """

    scissor: tuple[int, int, int, int]
    sub: tuple[float, float, float, float]


@dataclass(frozen=True)
class Layout:
    """Result of compute_layout: the canvas size + per-monitor draws.

    Monitors not in `draws` are left true-black by the clear (Primary-only mode).
    """

    canvas_w: int
    canvas_h: int
    draws: tuple[MonitorDraw, ...]


def to_gl_scissor(rect: Rect, vd: VirtualDesktop) -> tuple[int, int, int, int]:
    """Convert a virtual-coord Rect to a GL bottom-left scissor (x, y, w, h)."""
    # Pixel offset of the monitor within the window (top-left origin).
    x = rect.left - vd.origin_x
    top = rect.top - vd.origin_y
    # Flip y: GL counts from the bottom of the window.
    y = vd.height - (top + rect.height)
    return (x, y, rect.width, rect.height)


def _bezel_axis_offsets(starts: list[int], bezel_px: int) -> dict[int, int]:
    """Map each distinct edge coordinate to an accumulated bezel offset.

    For Span bezel-correction we want the image to flow *behind* the physical
    monitor gap, so each successive column/row is pushed out by one bezel width.
    Given the sorted distinct start coordinates along one axis, edge index i gets
    an offset of i * bezel_px. Returns {start_coord: offset}.
    """
    distinct = sorted(set(starts))
    return {coord: i * bezel_px for i, coord in enumerate(distinct)}


def compute_layout(
    vd: VirtualDesktop, mode: str, bezel_px: int = 0
) -> Layout:
    """Compute the canvas size and per-monitor draw list for a given mode.

    Single-monitor naturally collapses to one full-canvas draw in either mode.
    """
    if mode == MODE_PRIMARY:
        return _layout_primary(vd)
    return _layout_span(vd, max(0, bezel_px))


def _layout_primary(vd: VirtualDesktop) -> Layout:
    """Primary monitor shows the whole image; others stay black (no draw)."""
    idx = max(0, min(vd.primary_index, len(vd.monitors) - 1))
    mon = vd.monitors[idx]
    draw = MonitorDraw(
        scissor=to_gl_scissor(mon, vd),
        sub=(0.0, 0.0, 1.0, 1.0),  # this monitor IS the whole canvas
    )
    return Layout(canvas_w=mon.width, canvas_h=mon.height, draws=(draw,))


def _layout_span(vd: VirtualDesktop, bezel_px: int) -> Layout:
    """One image across the whole virtual desktop, sliced per monitor.

    Bezel correction widens the canvas by one bezel gap between each distinct
    column (x) and row (y) edge, and shifts each monitor's canvas position so the
    picture appears continuous across the physical seams.
    """
    x_off = _bezel_axis_offsets([m.left for m in vd.monitors], bezel_px)
    y_off = _bezel_axis_offsets([m.top for m in vd.monitors], bezel_px)
    n_x_gaps = len(x_off) - 1
    n_y_gaps = len(y_off) - 1

    canvas_w = vd.width + n_x_gaps * bezel_px
    canvas_h = vd.height + n_y_gaps * bezel_px
    # Guard against zero (single monitor with degenerate inputs).
    canvas_w = max(1, canvas_w)
    canvas_h = max(1, canvas_h)

    draws: list[MonitorDraw] = []
    for mon in vd.monitors:
        # Monitor's pixel position on the canvas (virtual offset + bezel push).
        cx = (mon.left - vd.origin_x) + x_off[mon.left]
        cy = (mon.top - vd.origin_y) + y_off[mon.top]
        sub = (
            cx / canvas_w,
            cy / canvas_h,
            (cx + mon.width) / canvas_w,
            (cy + mon.height) / canvas_h,
        )
        draws.append(MonitorDraw(scissor=to_gl_scissor(mon, vd), sub=sub))

    return Layout(canvas_w=canvas_w, canvas_h=canvas_h, draws=tuple(draws))


# ---------------------------------------------------------------------------
# Cover-fit: decide how an image maps onto a target rect without upscaling.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CoverFit:
    """How a source image covers a target rectangle.

    scale:     source-px -> screen-px factor that makes the image *cover* target.
    qualifies: True if the image covers without upscaling past native (scale<=1).
    uv0/uv1:   the texture sub-rectangle (normalized [0,1], v top-down) that maps
               onto the target rect, focal-centered. Valid whether or not it
               qualifies; the caller decides skip vs letterbox.
    """

    scale: float
    qualifies: bool
    uv0: tuple[float, float]
    uv1: tuple[float, float]


def cover_fit(
    target_w: float,
    target_h: float,
    image_w: int,
    image_h: int,
    focal: tuple[float, float] = (0.5, 0.5),
) -> CoverFit:
    """Compute a cover-fit of image (image_w x image_h) onto target (target_w x
    target_h), centered on `focal` (fractions of the image, v top-down).

    `target_w/h` should already INCLUDE the 2*M overscan needed for micro-shift;
    the micro-shift then slides a sub-window inside that overscan at render time.
    """
    if image_w <= 0 or image_h <= 0 or target_w <= 0 or target_h <= 0:
        return CoverFit(scale=0.0, qualifies=False, uv0=(0.0, 0.0), uv1=(1.0, 1.0))

    # Cover scale: the larger ratio fills both axes.
    scale = max(target_w / image_w, target_h / image_h)
    qualifies = scale <= 1.0 + 1e-9  # native covers without upscaling

    # Fraction of the texture visible across the target, per axis.
    u_span = min(1.0, target_w / (image_w * scale))
    v_span = min(1.0, target_h / (image_h * scale))

    fx = min(max(focal[0], 0.0), 1.0)
    fy = min(max(focal[1], 0.0), 1.0)
    # Center the visible span on the focal point, then clamp inside [0,1].
    u0 = min(max(fx - u_span / 2.0, 0.0), 1.0 - u_span)
    v0 = min(max(fy - v_span / 2.0, 0.0), 1.0 - v_span)
    return CoverFit(
        scale=scale,
        qualifies=qualifies,
        uv0=(u0, v0),
        uv1=(u0 + u_span, v0 + v_span),
    )
