"""Headless geometry tests: multi-monitor tiling, negative origins, Span/Primary,
bezel correction, cover-fit. None of this needs a GPU or a second display.
"""

from core.config import MODE_PRIMARY, MODE_SPAN
from core.geometry import (
    Rect,
    VirtualDesktop,
    compute_layout,
    cover_fit,
    to_gl_scissor,
)

WQHD = (2560, 1440)


def _single() -> VirtualDesktop:
    return VirtualDesktop.from_monitors([Rect(0, 0, 2560, 1440)])


def test_single_monitor_collapses_to_full_canvas():
    vd = _single()
    layout = compute_layout(vd, MODE_SPAN)
    assert layout.canvas_w == 2560 and layout.canvas_h == 1440
    assert len(layout.draws) == 1
    d = layout.draws[0]
    assert d.sub == (0.0, 0.0, 1.0, 1.0)
    assert d.scissor == (0, 0, 2560, 1440)


def test_single_monitor_same_in_both_modes():
    vd = _single()
    span = compute_layout(vd, MODE_SPAN)
    primary = compute_layout(vd, MODE_PRIMARY)
    assert span.draws[0].sub == primary.draws[0].sub
    assert span.draws[0].scissor == primary.draws[0].scissor


def test_two_side_by_side_span_subdivides_canvas():
    # Second monitor is LEFT of primary -> negative origin.
    left = Rect(-2560, 0, 0, 1440)
    right = Rect(0, 0, 2560, 1440)
    vd = VirtualDesktop.from_monitors([left, right], primary_index=1)
    layout = compute_layout(vd, MODE_SPAN)
    assert layout.canvas_w == 5120 and layout.canvas_h == 1440
    subs = sorted(d.sub for d in layout.draws)
    # Left half then right half of the canvas.
    assert subs[0] == (0.0, 0.0, 0.5, 1.0)
    assert subs[1] == (0.5, 0.0, 1.0, 1.0)


def test_negative_origin_scissor_flips_y_correctly():
    # Second monitor ABOVE the primary -> negative top.
    top = Rect(0, -1440, 2560, 0)
    bottom = Rect(0, 0, 2560, 1440)
    vd = VirtualDesktop.from_monitors([top, bottom], primary_index=1)
    assert vd.origin_y == -1440 and vd.height == 2880
    s_top = to_gl_scissor(top, vd)
    s_bottom = to_gl_scissor(bottom, vd)
    # GL is bottom-left origin: the physically-top monitor has the larger y.
    assert s_bottom == (0, 0, 2560, 1440)
    assert s_top == (0, 1440, 2560, 1440)


def test_primary_only_mode_draws_one_monitor():
    a = Rect(0, 0, 2560, 1440)
    b = Rect(2560, 0, 5120, 1440)
    vd = VirtualDesktop.from_monitors([a, b], primary_index=0)
    layout = compute_layout(vd, MODE_PRIMARY)
    assert len(layout.draws) == 1
    assert layout.canvas_w == 2560 and layout.canvas_h == 1440
    assert layout.draws[0].sub == (0.0, 0.0, 1.0, 1.0)
    assert layout.draws[0].scissor == (0, 0, 2560, 1440)


def test_bezel_widens_canvas_and_shifts_second_monitor():
    a = Rect(0, 0, 2560, 1440)
    b = Rect(2560, 0, 5120, 1440)
    vd = VirtualDesktop.from_monitors([a, b], primary_index=0)
    layout = compute_layout(vd, MODE_SPAN, bezel_px=100)
    assert layout.canvas_w == 5220  # 5120 + one 100px gap
    # Right monitor's left edge pushed out by the bezel.
    right = max(layout.draws, key=lambda d: d.sub[0])
    assert abs(right.sub[0] - (2660 / 5220)) < 1e-9


def test_cover_fit_qualifies_when_image_exceeds_target():
    # 4K image easily covers a WQHD-ish target without upscaling.
    fit = cover_fit(2700, 1580, 3840, 2160)
    assert fit.qualifies
    assert fit.scale <= 1.0
    # Only part of the texture is visible (cover crop).
    assert (fit.uv1[0] - fit.uv0[0]) <= 1.0
    assert (fit.uv1[1] - fit.uv0[1]) <= 1.0


def test_cover_fit_rejects_when_upscale_required():
    # Tiny image cannot cover a big target without upscaling.
    fit = cover_fit(2700, 1580, 800, 600)
    assert not fit.qualifies
    assert fit.scale > 1.0
