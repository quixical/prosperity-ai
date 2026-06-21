"""Pillow image -> moderngl texture. LINEAR filtering, mipmaps for clean
downscaling (we always downscale to cover; we never upscale past native).
"""

from __future__ import annotations

from dataclasses import dataclass

import moderngl

from platform_linux.imageops import open_image


@dataclass
class GLImage:
    texture: "moderngl.Texture"
    width: int
    height: int

    def release(self) -> None:
        try:
            self.texture.release()
        except Exception:
            pass


def load_image(ctx: "moderngl.Context", path: str) -> GLImage:
    """Decode `path` and upload as an RGB texture.

    Row 0 (image top) is uploaded at v=0, matching the v-top-down convention used
    by core.geometry and the shaders. Raises on decode failure (caller handles).
    """
    im = open_image(path)          # RAW-aware (embedded preview) + EXIF-oriented
    try:
        rgb = im.convert("RGB")
        w, h = rgb.size
        data = rgb.tobytes()
    finally:
        im.close()

    tex = ctx.texture((w, h), 3, data)
    tex.build_mipmaps()
    # Trilinear minification (heavy downscale), linear magnification (sub-pixel
    # micro-shift smoothness). Clamp so the cover window never wraps at edges.
    tex.filter = (moderngl.LINEAR_MIPMAP_LINEAR, moderngl.LINEAR)
    tex.repeat_x = False
    tex.repeat_y = False
    return GLImage(texture=tex, width=w, height=h)
