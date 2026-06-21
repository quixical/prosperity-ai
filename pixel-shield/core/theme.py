"""Theme loading: themes/<name>/theme.json (schema 1) with glob fallback.

PORTABLE: stdlib only. Does NOT decode pixels (that's render/textures.py); it only
resolves the ordered list of image file paths + metadata. Drop-in folders with no
theme.json still work via the glob fallback, so the user can just drop images in.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

THEME_SCHEMA = 1

# Standard formats Pillow decodes directly.
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff")
# Camera RAW formats (decoded via rawpy's embedded preview in platform_linux.imageops).
RAW_EXTENSIONS = (
    ".raf", ".cr2", ".cr3", ".nef", ".nrw", ".arw", ".srf", ".sr2", ".dng",
    ".orf", ".rw2", ".pef", ".rwl", ".3fr", ".dcr", ".kdc", ".mrw", ".x3f", ".erf",
)
# Everything we accept as a picture, in glob order.
ALL_EXTENSIONS = IMAGE_EXTENSIONS + RAW_EXTENSIONS


@dataclass
class ThemeImage:
    """One image entry. `focal` is a normalized (x, y) in [0,1], v top-down."""

    file: str                       # absolute path on disk
    title: str = ""
    credit: str = ""
    focal: tuple[float, float] = (0.5, 0.5)


@dataclass
class Theme:
    name: str
    version: str = "0"
    author: str = ""
    images: list[ThemeImage] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.images)


def _coerce_focal(value) -> tuple[float, float]:
    try:
        x, y = float(value[0]), float(value[1])
        return (min(max(x, 0.0), 1.0), min(max(y, 0.0), 1.0))
    except (TypeError, ValueError, IndexError):
        return (0.5, 0.5)


# Subdirectories never scanned: our own favorites output (old per-folder "Favorites"
# and the new single "Pixel Shield Favorites"). Hidden dirs (".*") are skipped too.
_EXCLUDED_DIRS = {"favorites", "pixel shield favorites"}


def _glob_images(folder: Path) -> list[ThemeImage]:
    """Fallback: every supported image anywhere UNDER the folder (recursive), so a
    whole library tree of subfolders is used in its totality. Sorted by path."""
    found: list[Path] = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs
                   if d.lower() not in _EXCLUDED_DIRS and not d.startswith(".")]
        for name in files:
            if os.path.splitext(name)[1].lower() in ALL_EXTENSIONS:
                found.append(Path(root) / name)
    found.sort(key=lambda p: str(p).lower())
    return [ThemeImage(file=str(p), title=p.stem) for p in found]


def load_theme(theme_dir: str | Path) -> Theme:
    """Load a theme from its directory.

    If theme.json is present and lists images[], use those (resolved relative to
    the theme dir). If images[] is absent/empty or theme.json is missing/corrupt,
    glob the folder. Entries whose files don't exist are dropped.
    """
    folder = Path(theme_dir)
    name = folder.name
    manifest = folder / "theme.json"

    meta: dict = {}
    declared: list[ThemeImage] = []
    if manifest.is_file():
        try:
            meta = json.loads(manifest.read_text(encoding="utf-8")) or {}
        except (json.JSONDecodeError, OSError):
            meta = {}
        name = meta.get("name", name)
        for entry in meta.get("images", []) or []:
            if not isinstance(entry, dict) or "file" not in entry:
                continue
            fpath = (folder / entry["file"]).resolve()
            declared.append(
                ThemeImage(
                    file=str(fpath),
                    title=entry.get("title", Path(entry["file"]).stem),
                    credit=entry.get("credit", ""),
                    focal=_coerce_focal(entry.get("focal", (0.5, 0.5))),
                )
            )

    images = declared if declared else _glob_images(folder)
    # Drop anything that isn't actually on disk so the renderer never faults.
    images = [img for img in images if Path(img.file).is_file()]

    return Theme(
        name=name,
        version=str(meta.get("version", "0")),
        author=meta.get("author", ""),
        images=images,
    )


def list_themes(themes_root: str | Path) -> list[str]:
    """Names of all theme subdirectories under the themes root."""
    root = Path(themes_root)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())
