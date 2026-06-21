"""Image decoding that also handles camera RAW.

Pillow can't read camera RAW (.RAF/.CR2/.NEF/...). For those we pull the embedded
full-size JPEG preview via rawpy/libraw (fast — ~100ms, full resolution — no heavy
demosaic), falling back to a full decode only if a file has no preview. Regular
formats go straight through Pillow. EXIF orientation is applied so portrait shots
display upright. One decoder shared by the GL texture loader and the favorites
thumbnailer.
"""

from __future__ import annotations

import io
from pathlib import Path

from PIL import Image, ImageOps

from core.theme import RAW_EXTENSIONS


def is_raw(path: str | Path) -> bool:
    return Path(path).suffix.lower() in RAW_EXTENSIONS


def _open_raw(path: str | Path) -> Image.Image:
    import rawpy

    with rawpy.imread(str(path)) as raw:
        thumb = None
        try:
            thumb = raw.extract_thumb()
        except Exception:
            thumb = None
        if thumb is not None:
            if thumb.format == rawpy.ThumbFormat.JPEG:
                img = Image.open(io.BytesIO(thumb.data))
                img.load()
                return img
            if thumb.format == rawpy.ThumbFormat.BITMAP:
                return Image.fromarray(thumb.data)
        # No embedded preview: full demosaic (slow, but correct).
        return Image.fromarray(raw.postprocess())


def open_image(path: str | Path) -> Image.Image:
    """Return a loaded PIL image for `path` (RAW or regular), EXIF-oriented."""
    img = _open_raw(path) if is_raw(path) else Image.open(path)
    try:
        img = ImageOps.exif_transpose(img)
    except Exception:
        pass
    return img
