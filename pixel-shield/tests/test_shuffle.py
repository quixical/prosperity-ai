"""Shuffle-bag tests: no repeats within a lap, reshuffles across laps, no seam
repeat, and different launches start differently."""

import random

from core.shuffle import ShuffleBag


def test_each_lap_shows_every_index_once():
    bag = ShuffleBag(5, random.Random(1))
    lap = [bag.next() for _ in range(5)]
    assert sorted(lap) == [0, 1, 2, 3, 4]


def test_two_laps_each_complete_no_repeats_within():
    bag = ShuffleBag(6, random.Random(2))
    lap1 = [bag.next() for _ in range(6)]
    lap2 = [bag.next() for _ in range(6)]
    assert sorted(lap1) == list(range(6))
    assert sorted(lap2) == list(range(6))


def test_no_repeat_across_lap_seam():
    # The last of one lap must not equal the first of the next.
    for seed in range(50):
        bag = ShuffleBag(4, random.Random(seed))
        seq = [bag.next() for _ in range(8)]
        assert seq[3] != seq[4]


def test_empty_and_single():
    assert ShuffleBag(0).next() is None
    one = ShuffleBag(1)
    assert one.next() == 0 and one.next() == 0


def test_different_seeds_diverge():
    a = [ShuffleBag(8, random.Random(s)).next() for s in range(8)]
    # Not all launches start on the same picture (true of entropy seeding too).
    assert len(set(a)) > 1


def test_is_a_permutation_not_sequential():
    # With a fixed seed the order is shuffled, not 0,1,2,3,4...
    bag = ShuffleBag(8, random.Random(123))
    lap = [bag.next() for _ in range(8)]
    assert lap != list(range(8))
