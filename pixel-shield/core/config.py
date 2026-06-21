"""Configuration model for OLED Maintainer.

PORTABLE: stdlib only (json, dataclasses, pathlib). No win32/pygame/tk imports.
Path *resolution* (%APPDATA%, %PROGRAMDATA%) lives in platform_linux.paths; this
module only knows how to (de)serialize a Config given a concrete path. A C++/Rust
rewrite can mirror this struct + JSON schema 1:1.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

CONFIG_SCHEMA = 1

# Multi-monitor modes (v1). Per-monitor is deferred.
MODE_SPAN = "span"          # one image stretched across the whole virtual desktop
MODE_PRIMARY = "primary"    # primary monitor shows the image, others true-black
VALID_MULTIMON_MODES = (MODE_SPAN, MODE_PRIMARY)


@dataclass
class Config:
    """User-tunable settings. Defaults match the ratified v1 spec."""

    schema: int = CONFIG_SCHEMA
    theme: str = "sample"

    # WALLPAPER (Part 1): cycles its folder ONE picture per completed figure-8
    # (~hours), drifting via the micro-shift in between. Sequential, not random.
    # wallpaper_folder = pictures folder (blank -> the theme folder).
    # wallpaper_image  = optional starting picture (filename); blank = first.
    # wallpaper_fade_sec = transition length; 0 = hard cut.
    wallpaper_folder: str = ""
    wallpaper_image: str = ""
    wallpaper_fade_sec: float = 3.0

    # SCREENSAVER (Part 2): idle-triggered RANDOM slideshow. Its own pictures folder
    # (blank -> the theme folder) and the idle time before it takes over.
    screensaver_folder: str = ""
    # Where Space-to-favorite saves a thumbnail + shortcut (blank -> Pictures\Pixel
    # Shield Favorites).
    favorites_folder: str = ""
    screensaver_idle_min: float = 10.0   # minutes idle before the screensaver starts
    image_duration_sec: float = 30.0     # how long each image is held
    crossfade_duration_sec: float = 2.0  # cross-fade time between images

    # Micro-shift (the burn-in core). C = seconds per 1px of travel.
    cadence_sec_per_px: float = 10.0     # C
    overscan_margin_px: int = 70         # M (figure-8 wanders in a 2M x 2M box)

    # Multi-monitor / compositing
    bezel_width_px: int = 0              # physical gap correction for Span
    multimonitor_mode: str = MODE_SPAN

    # Optional override for the themes pack directory (defaults to %PROGRAMDATA%).
    themes_path: str | None = None

    # ---- validation -----------------------------------------------------

    def clamp(self) -> "Config":
        """Coerce values into sane ranges. Returns self for chaining."""
        self.image_duration_sec = max(1.0, float(self.image_duration_sec))
        self.crossfade_duration_sec = max(0.0, float(self.crossfade_duration_sec))
        # Cross-fade cannot exceed the hold time, or images would never settle.
        self.crossfade_duration_sec = min(
            self.crossfade_duration_sec, self.image_duration_sec
        )
        self.cadence_sec_per_px = max(0.1, float(self.cadence_sec_per_px))
        self.wallpaper_fade_sec = max(0.0, float(self.wallpaper_fade_sec))
        self.screensaver_idle_min = max(1.0, float(self.screensaver_idle_min))
        self.overscan_margin_px = max(1, int(self.overscan_margin_px))
        self.bezel_width_px = max(0, int(self.bezel_width_px))
        if self.multimonitor_mode not in VALID_MULTIMON_MODES:
            self.multimonitor_mode = MODE_SPAN
        return self

    # ---- serialization --------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in (data or {}).items() if k in known}
        return cls(**filtered).clamp()

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        """Load config from a JSON file. Missing/corrupt file -> defaults."""
        p = Path(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return cls().clamp()
        return cls.from_dict(data)

    def save(self, path: str | Path) -> None:
        """Persist to JSON, creating parent directories as needed."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        self.clamp()
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
