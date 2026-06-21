"""Micro-shift tests: the CRITICAL cadence guarantee — path speed never exceeds
1px/C even where the figure-8 and precession velocities align — plus the overscan
box containment. Pure math, fully headless.
"""

import math

from core.microshift import (
    DEFAULT_K,
    SQRT5,
    angular_omega,
    centered_offset,
    peak_speed_px_per_sec,
    required_overscan,
    speed_at,
    window_offset,
)

C = 10.0   # cadence: 1px per 10s
M = 70.0   # nominal margin
K = DEFAULT_K


def test_omega_sizes_peak_speed_to_cadence():
    omega = angular_omega(C, M, K)
    analytic_peak = omega * M * (SQRT5 + 1.25 / K)
    assert math.isclose(analytic_peak, peak_speed_px_per_sec(C), rel_tol=1e-12)


def test_speed_never_exceeds_cadence_cap():
    cap = peak_speed_px_per_sec(C)  # 0.1 px/s
    omega = angular_omega(C, M, K)
    precession_period = K * 2.0 * math.pi / omega  # longest cycle in the system

    max_speed = 0.0
    n = 60000
    for i in range(n):
        t = precession_period * i / n
        max_speed = max(max_speed, speed_at(t, C, M, K))

    # Holds even at velocity alignment (small numeric slack for the derivative).
    assert max_speed <= cap * 1.001
    # ...and the design is tight — it really does approach the cap (cadence is
    # meaningful, not an over-conservative crawl).
    assert max_speed >= cap * 0.9


def test_window_offset_stays_inside_overscan_box():
    reserve = required_overscan(M)        # 1.25 * M
    box = 2.0 * reserve
    omega = angular_omega(C, M, K)
    period = K * 2.0 * math.pi / omega

    n = 40000
    for i in range(n):
        t = period * i / n
        ox, oy = window_offset(t, C, M, K)
        assert -1e-6 <= ox <= box + 1e-6
        assert -1e-6 <= oy <= box + 1e-6


def test_centered_offset_magnitude_bounded_by_1p25_M():
    # |a| peaks at 1.25*M; rotation preserves magnitude.
    omega = angular_omega(C, M, K)
    period = K * 2.0 * math.pi / omega
    n = 40000
    max_mag = 0.0
    for i in range(n):
        t = period * i / n
        rx, ry = centered_offset(t, C, M, K)
        max_mag = max(max_mag, math.hypot(rx, ry))
    assert max_mag <= 1.25 * M + 1e-6
    assert max_mag >= 1.24 * M  # actually reaches the bound


def test_offset_continuous_no_discrete_jumps():
    # Adjacent frames at 60fps must move sub-pixel (smooth, no jumps).
    dt = 1.0 / 60.0
    prev = centered_offset(0.0, C, M, K)
    for i in range(1, 5000):
        cur = centered_offset(i * dt, C, M, K)
        step = math.hypot(cur[0] - prev[0], cur[1] - prev[1])
        assert step < 0.05  # well under 1px/frame
        prev = cur
