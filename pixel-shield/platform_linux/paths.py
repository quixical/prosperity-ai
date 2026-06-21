"""Linux path resolution for config + theme packs (XDG Base Directory spec).

    config  -> $XDG_CONFIG_HOME/pixel-shield/config.json      (~/.config/...)
    state   -> $XDG_STATE_HOME/pixel-shield/                  (~/.local/state/...)
    themes  -> $XDG_DATA_HOME/pixel-shield/themes/            (overridable in config)
    favorites -> ~/Pictures/Pixel Shield Favorites

Kept platform-specific so core.config stays portable. Mirrors platform_win.paths.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_DIR_NAME = "pixel-shield"


def _xdg(var: str, default: Path) -> Path:
    val = os.environ.get(var, "").strip()
    return Path(val) if val else default


def config_home() -> Path:
    return _xdg("XDG_CONFIG_HOME", Path.home() / ".config")


def data_home() -> Path:
    return _xdg("XDG_DATA_HOME", Path.home() / ".local" / "share")


def state_home() -> Path:
    return _xdg("XDG_STATE_HOME", Path.home() / ".local" / "state")


def app_config_dir() -> Path:
    return config_home() / APP_DIR_NAME


def app_state_dir() -> Path:
    return state_home() / APP_DIR_NAME


def config_path() -> Path:
    return app_config_dir() / "config.json"


def wallpaper_stop_file() -> Path:
    """Sentinel that signals a running wallpaper instance to exit cleanly."""
    return app_state_dir() / "wallpaper.stop"


def _pictures_dir() -> Path:
    """The user's Pictures dir, honoring XDG user-dirs if configured."""
    cfg = config_home() / "user-dirs.dirs"
    try:
        for line in cfg.read_text(encoding="utf-8").splitlines():
            if line.startswith("XDG_PICTURES_DIR"):
                raw = line.split("=", 1)[1].strip().strip('"')
                return Path(os.path.expandvars(raw))
    except OSError:
        pass
    return Path.home() / "Pictures"


def favorites_dir(override: str | None = None) -> Path:
    """Where Space-to-favorite saves thumbnails + symlinks.

    Default: ~/Pictures/Pixel Shield Favorites.
    """
    if override:
        return Path(os.path.expanduser(override))
    return _pictures_dir() / "Pixel Shield Favorites"


def bundled_themes_root() -> Path:
    """The themes/ folder shipped with the app (source tree or frozen bundle)."""
    import sys

    if getattr(sys, "frozen", False):
        meipass = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "themes"
        if meipass.is_dir():
            return meipass
    # platform_linux/paths.py -> project root /themes
    return Path(__file__).resolve().parent.parent / "themes"


def default_themes_root() -> Path:
    return data_home() / APP_DIR_NAME / "themes"


def themes_root(override: str | None) -> Path:
    if override:
        return Path(os.path.expanduser(override))
    return default_themes_root()


def resolve_theme_dir(theme_name: str | None, themes_path_override: str | None) -> Path:
    """Locate a theme directory: user themes root first, then the bundled copy.

    Falls back to the bundled 'sample' theme so callers always get a real path.
    """
    name = theme_name or "sample"
    for root in (themes_root(themes_path_override), bundled_themes_root()):
        cand = root / name
        if cand.is_dir():
            return cand
    return bundled_themes_root() / "sample"


def to_accessible_path(folder: str) -> Path:
    """Resolve a configured folder to a usable path WITHOUT requiring it to exist.

    On Linux, network shares (NFS/SMB/gvfs) appear as ordinary paths, so unlike
    the Windows mapped-drive translation this just expands ~ and environment vars.
    Crucially it does NOT test existence: a share that isn't mounted yet right
    after login must resolve to its real path and simply yield no images until
    reachable, never silently fall back to a different folder.
    """
    return Path(os.path.expandvars(os.path.expanduser(folder)))


def source_dir(explicit_folder: str | None, theme_name: str | None,
               themes_path_override: str | None) -> Path:
    """Pictures folder for the wallpaper or screensaver.

    A configured folder is used AS-IS (no is_dir check) so a momentarily-missing
    network mount can't make us revert to the bundled theme. Only fall back to the
    named theme when no folder is configured at all.
    """
    if explicit_folder:
        return to_accessible_path(explicit_folder)
    return resolve_theme_dir(theme_name, themes_path_override)
