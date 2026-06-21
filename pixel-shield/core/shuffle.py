"""Shuffle-bag for the screensaver's random picture order.

PORTABLE: stdlib only. Yields indices 0..n-1 in random order with NO repeat until
the whole set is shown, then reshuffles for a fresh order — and avoids showing the
same picture twice across the lap seam. Seeded from entropy by default so every
launch starts on a different picture in a different order (the user's key gripe with
Windows' fixed alphabetical slideshow). Inject a seeded Random for deterministic
tests.
"""

from __future__ import annotations

import random


class ShuffleBag:
    def __init__(self, n: int, rng: random.Random | None = None) -> None:
        self.n = max(0, int(n))
        self.rng = rng or random.Random()  # entropy-seeded unless one is provided
        self._order: list[int] = []
        self._pos = 0
        self._last: int | None = None
        if self.n:
            self._reshuffle()

    def _reshuffle(self) -> None:
        order = list(range(self.n))
        self.rng.shuffle(order)
        # Don't repeat the previous lap's last picture as this lap's first.
        if self.n > 1 and order[0] == self._last:
            order[0], order[1] = order[1], order[0]
        self._order = order
        self._pos = 0

    def next(self) -> int | None:
        """Next index, or None if the bag is empty."""
        if self.n == 0:
            return None
        if self.n == 1:
            self._last = 0
            return 0
        if self._pos >= len(self._order):
            self._reshuffle()
        i = self._order[self._pos]
        self._pos += 1
        self._last = i
        return i
