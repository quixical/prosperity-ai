"""Favorite the currently-shown picture (screensaver Space hotkey).

Saves into a SINGLE folder (default ~/Pictures/Pixel Shield Favorites): a small
thumbnail JPG for browsing + a SYMLINK to the ORIGINAL file (never a full copy).
De-duplicated, so re-favoriting the same photo is a no-op. If a symlink can't be
created (e.g. the favorites folder is on a filesystem that forbids them) we fall
back to a .desktop launcher pointing at the original, then a plain .txt address.

Mirrors platform_win.favorites (which uses a .lnk shortcut).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from platform_linux.imageops import open_image

THUMB_MAX = 320


def _make_desktop_launcher(path: Path, target: Path) -> bool:
    """Fallback link: a .desktop file that opens the original in the default app."""
    try:
        content = (
            "[Desktop Entry]\n"
            "Type=Link\n"
            f"Name={target.name}\n"
            f"URL=file://{target}\n"
        )
        path.write_text(content, encoding="utf-8")
        return True
    except OSError:
        return False


def favorite(image_path: str, dest_dir) -> Path | None:
    """Record `image_path` as a favorite in `dest_dir`. Returns the folder or None.

    Writes `<name>_<hash>.jpg` (thumbnail) and `<name>_<hash>` symlink to the
    original. The hash keeps names unique across same-named files in different
    subfolders and makes the operation idempotent.
    """
    src = Path(image_path)
    if not src.is_file():
        return None
    dest = Path(dest_dir)
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None

    target = src.resolve()
    digest = hashlib.sha1(str(target).encode("utf-8", "ignore")).hexdigest()[:8]
    base = f"{src.stem}_{digest}"
    # Distinct names so the thumbnail (.thumb.jpg) never collides with the link,
    # which keeps the original's extension for a clean, openable name.
    link = dest / f"{base}{src.suffix}"
    thumb = dest / f"{base}.thumb.jpg"

    if link.exists() or link.is_symlink() or thumb.exists():
        return dest  # already favorited

    # Thumbnail (best-effort; RAW-aware via embedded preview).
    try:
        im = open_image(src)
        try:
            rgb = im.convert("RGB")
            rgb.thumbnail((THUMB_MAX, THUMB_MAX))
            rgb.save(thumb, "JPEG", quality=85)
        finally:
            im.close()
    except Exception:
        pass

    # Symlink to the original; fall back to a .desktop, then a plain-text address.
    try:
        link.symlink_to(target)
    except OSError:
        if not _make_desktop_launcher(dest / f"{base}.desktop", target):
            try:
                (dest / f"{base}.txt").write_text(str(target), encoding="utf-8")
            except OSError:
                pass

    return dest
