"""Wallpaper picture-rotation schedule: advance one picture per figure-8, sequential,
with a fade window or hard cut. Pure function -> tested at an arbitrary timescale.
"""

import math

from core.microshift import figure8_period, picture_schedule


def test_figure8_period_is_about_2_9_hours_at_defaults():
    p = figure8_period(10.0, 70)
    assert math.isclose(p, 10522, rel_tol=1e-3)   # ~2.92 hours


def test_single_image_never_advances():
    for t in (0.0, 5.0, 1e6):
        assert picture_schedule(t, 100.0, 3.0, 1, 0) == (0, None, 0.0)


def test_holds_through_first_cycle():
    # Whole first cycle shows the start picture, no transition.
    assert picture_schedule(0.0, 100.0, 3.0, 4, 0) == (0, None, 0.0)
    assert picture_schedule(50.0, 100.0, 3.0, 4, 0) == (0, None, 0.0)
    assert picture_schedule(99.9, 100.0, 3.0, 4, 0) == (0, None, 0.0)


def test_hard_cut_advances_on_boundary():
    # fade_sec = 0 -> instant swap each cycle, wrapping.
    assert picture_schedule(0.0, 100.0, 0.0, 3, 0) == (0, None, 0.0)
    assert picture_schedule(100.0, 100.0, 0.0, 3, 0) == (1, None, 0.0)
    assert picture_schedule(200.0, 100.0, 0.0, 3, 0) == (2, None, 0.0)
    assert picture_schedule(300.0, 100.0, 0.0, 3, 0) == (0, None, 0.0)  # wrap


def test_fade_window_cross_fades_prev_to_cur():
    P, F = 100.0, 4.0
    # At the boundary the fade has just begun: from prev(0) to cur(1), fade 0.
    a, b, f = picture_schedule(100.0, P, F, 4, 0)
    assert (a, b) == (0, 1) and math.isclose(f, 0.0)
    # One second in -> 25% blended.
    a, b, f = picture_schedule(101.0, P, F, 4, 0)
    assert (a, b) == (0, 1) and math.isclose(f, 0.25)
    # Just before fade end -> ~100%.
    a, b, f = picture_schedule(103.9, P, F, 4, 0)
    assert (a, b) == (0, 1) and f > 0.9
    # After the fade window -> settled on picture 1, no transition.
    assert picture_schedule(104.1, P, F, 4, 0) == (1, None, 0.0)


def test_start_index_offsets_sequence_and_wraps():
    # Start on picture 2 of 3; next cycle wraps to 0.
    assert picture_schedule(0.0, 100.0, 0.0, 3, 2) == (2, None, 0.0)
    assert picture_schedule(100.0, 100.0, 0.0, 3, 2) == (0, None, 0.0)
    assert picture_schedule(200.0, 100.0, 0.0, 3, 2) == (1, None, 0.0)


def test_cycles_through_every_picture_once_per_lap():
    n, P = 5, 100.0
    seen = {picture_schedule(c * P + P / 2, P, 3.0, n, 0)[0] for c in range(n)}
    assert seen == set(range(n))  # all five shown across one lap
