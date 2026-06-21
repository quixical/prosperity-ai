"""Config tests: defaults, clamping, JSON round-trip, unknown-key tolerance."""

from pathlib import Path

from core.config import MODE_SPAN, Config


def test_defaults_match_spec():
    c = Config()
    assert c.overscan_margin_px == 70
    assert c.cadence_sec_per_px == 10.0
    assert c.multimonitor_mode == MODE_SPAN


def test_clamp_bounds_and_crossfade_not_exceeding_hold():
    c = Config(image_duration_sec=5, crossfade_duration_sec=99, overscan_margin_px=0,
               cadence_sec_per_px=0, multimonitor_mode="bogus").clamp()
    assert c.crossfade_duration_sec <= c.image_duration_sec
    assert c.overscan_margin_px >= 1
    assert c.cadence_sec_per_px >= 0.1
    assert c.multimonitor_mode == MODE_SPAN


def test_round_trip(tmp_path: Path):
    p = tmp_path / "config.json"
    c = Config(theme="mypack", bezel_width_px=12, overscan_margin_px=55)
    c.save(p)
    loaded = Config.load(p)
    assert loaded.theme == "mypack"
    assert loaded.bezel_width_px == 12
    assert loaded.overscan_margin_px == 55


def test_folders_and_idle_round_trip(tmp_path: Path):
    p = tmp_path / "config.json"
    Config(wallpaper_folder=r"D:\wp", screensaver_folder=r"D:\ss",
           screensaver_idle_min=15).save(p)
    loaded = Config.load(p)
    assert loaded.wallpaper_folder == r"D:\wp"
    assert loaded.screensaver_folder == r"D:\ss"
    assert loaded.screensaver_idle_min == 15


def test_idle_minutes_clamped_to_minimum():
    assert Config(screensaver_idle_min=0).clamp().screensaver_idle_min >= 1.0


def test_unknown_keys_ignored(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text('{"theme": "x", "future_setting": 1, "overscan_margin_px": 40}',
                 encoding="utf-8")
    loaded = Config.load(p)
    assert loaded.theme == "x"
    assert loaded.overscan_margin_px == 40


def test_missing_file_returns_defaults(tmp_path: Path):
    loaded = Config.load(tmp_path / "nope.json")
    assert loaded.overscan_margin_px == 70
