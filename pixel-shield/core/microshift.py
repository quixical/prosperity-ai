"""Micro-shift: the burn-in mitigation core.

PORTABLE: pure float math, deterministic in `time`. No platform imports.

The image's sampling window wanders along a rotating Lissajous figure-8 so no
pixel sits still. Per the ratified spec:

    centered path   a(tau) = M * (sin tau, sin 2tau)         tau = omega * time
    precession      the figure-8 orientation rotates at angular rate omega / k
    window offset   off = reserve + R(phi) a(tau)            phi = (omega/k)*time

Cadence guarantee
-----------------
"1px every C seconds" is enforced as a PEAK path-speed cap: the window never
travels faster than 1/C px/s, even at the worst instant where the figure-8 and
the precession velocities align. With

    omega = 1 / (C * M * (sqrt(5) + 1.25/k))

the peak speed is bounded by omega*M*(sqrt(5) + 1.25/k) = 1/C px/s, because:
  * figure-8 peak speed  = omega*M*sqrt(5)        (at the center crossing, tau=0)
  * precession adds up to omega*M*1.25/k          (1.25 = max|a|/M, see below)

Overscan note (correctness)
---------------------------
The unrotated figure-8 stays in a 2M box per axis, but |a(tau)| peaks at 1.25*M
(at sin^2(tau)=5/8), so once the pattern ROTATES, a single axis can swing to
+/-1.25*M. To guarantee the sampling window never reveals a black edge, the
renderer must reserve `required_overscan(M)` = 1.25*M per side, NOT M. `M` stays
the user-facing "nominal margin"; 1.25*M is the physically-required reserve.
"""

from __future__ import annotations

import math

SQRT5 = math.sqrt(5.0)

# Peak magnitude of the centered figure-8 in units of M. |a|^2 = sin^2 t + sin^2 2t
# maximizes at sin^2 t = 5/8, giving |a|^2 = 1.5625 -> |a| = 1.25 M.
FIG8_MAG = 1.25

DEFAULT_K = 8  # precession divisor: figure-8 rotates k times slower than it traces


def angular_omega(cadence_sec_per_px: float, margin_px: float, k: int = DEFAULT_K) -> float:
    """omega (rad/s) sized so peak path speed == 1 / cadence  px/s."""
    return 1.0 / (cadence_sec_per_px * margin_px * (SQRT5 + FIG8_MAG / k))


def required_overscan(margin_px: float) -> float:
    """Per-side overscan the renderer must reserve so the rotated figure-8 never
    reveals an edge. Equals 1.25 * nominal margin."""
    return FIG8_MAG * margin_px


def centered_offset(
    time: float, cadence_sec_per_px: float, margin_px: float, k: int = DEFAULT_K
) -> tuple[float, float]:
    """The zero-mean, rotated figure-8 vector at `time` (px). |result| <= 1.25*M."""
    omega = angular_omega(cadence_sec_per_px, margin_px, k)
    tau = omega * time
    phi = (omega / k) * time

    # Base figure-8 (vertical: y oscillates at double frequency).
    ax = margin_px * math.sin(tau)
    ay = margin_px * math.sin(2.0 * tau)

    # Slow precession: rotate the whole pattern by phi.
    c, s = math.cos(phi), math.sin(phi)
    rx = c * ax - s * ay
    ry = s * ax + c * ay
    return (rx, ry)


def window_offset(
    time: float, cadence_sec_per_px: float, margin_px: float, k: int = DEFAULT_K
) -> tuple[float, float]:
    """Top-left of the sampling window in px, in [0, 2*required_overscan].

    This is what the renderer adds to the image's cover-fit origin. Centered at
    `required_overscan` so the window sits mid-box at time 0.
    """
    reserve = required_overscan(margin_px)
    rx, ry = centered_offset(time, cadence_sec_per_px, margin_px, k)
    return (reserve + rx, reserve + ry)


def figure8_period(cadence_sec_per_px: float, margin_px: float, k: int = DEFAULT_K) -> float:
    """Seconds for one full figure-8 trace (tau: 0 -> 2*pi). At C=10,M=70,k=8 this
    is ~2.9 hours, which is the wallpaper's per-picture advance interval."""
    return 2.0 * math.pi / angular_omega(cadence_sec_per_px, margin_px, k)


def picture_schedule(
    elapsed: float, fig8_period: float, fade_sec: float, n_images: int,
    start_idx: int = 0,
) -> tuple[int, int | None, float]:
    """Stateless wallpaper picture rotation as a pure function of elapsed time.

    The wallpaper advances ONE picture each completed figure-8 (every fig8_period s),
    sequentially through the folder. The transition is a fade over the first
    `fade_sec` seconds of each new cycle (0 = hard cut). The figure-8 offset is at
    center on the cycle boundary, so that fade window sits on a natural seam.

    Returns (from_idx, to_idx_or_None, fade): render image `from_idx`; if `to_idx`
    is not None a transition is in progress, cross-fading from->to by `fade` in
    [0,1]. With <=1 image it always returns (start_idx, None, 0.0).
    """
    if n_images <= 1:
        return (max(0, start_idx) % max(1, n_images), None, 0.0)

    cycle = int(elapsed / fig8_period)
    cur = (start_idx + cycle) % n_images
    if fade_sec > 0.0 and cycle > 0:
        t_in = elapsed - cycle * fig8_period
        if t_in < fade_sec:
            prev = (start_idx + cycle - 1) % n_images
            return (prev, cur, t_in / fade_sec)
    return (cur, None, 0.0)


def peak_speed_px_per_sec(cadence_sec_per_px: float) -> float:
    """The cadence cap: 1 px per C seconds."""
    return 1.0 / cadence_sec_per_px


def speed_at(
    time: float,
    cadence_sec_per_px: float,
    margin_px: float,
    k: int = DEFAULT_K,
    dt: float = 1e-4,
) -> float:
    """Numerical path speed (px/s) at `time` — used by tests to verify the cap."""
    x0, y0 = centered_offset(time - dt, cadence_sec_per_px, margin_px, k)
    x1, y1 = centered_offset(time + dt, cadence_sec_per_px, margin_px, k)
    return math.hypot(x1 - x0, y1 - y0) / (2.0 * dt)
