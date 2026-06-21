"""Offscreen GL canvas: render a frame to an FBO and read it back as a PIL image.

On GNOME/Mutter there is no z-order slot for a live client window between the
compositor's background and the desktop icons, so the wallpaper can't be a visible
GL window (verified on GNOME 46 / X11). Instead we render each micro-shifted frame
to an offscreen framebuffer on the GPU (the renderer and all UV/micro-shift math
are unchanged) and hand the pixels to platform_linux.wallpaper_host to install as
the desktop background, which IS drawn behind the icons.

Because the motion is ~1px / 10s, frames are nearly identical between updates, so a
low refresh cadence is visually continuous and the compositor's per-update fade is
imperceptible.
"""

from __future__ import annotations

import moderngl
from PIL import Image


class OffscreenCanvas:
    """A standalone GL context + RGBA framebuffer sized to the virtual desktop."""

    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height
        # Standalone (windowless) context; EGL picks up the NVIDIA GPU directly.
        self.ctx = moderngl.create_standalone_context(require=330)
        self._color = self.ctx.texture((width, height), 4)
        self.fbo = self.ctx.framebuffer(color_attachments=[self._color])
        self.fbo.use()
        self.ctx.viewport = (0, 0, width, height)

    def use(self) -> None:
        """Bind the FBO as the render target before calling Renderer.render()."""
        self.fbo.use()
        self.ctx.viewport = (0, 0, self.width, self.height)

    def to_image(self) -> Image.Image:
        """Read the rendered frame as an upright (top-left origin) RGB PIL image."""
        data = self.fbo.read(components=3, alignment=1)
        img = Image.frombytes("RGB", (self.width, self.height), data)
        # GL framebuffers are bottom-left origin; flip to image top-left.
        return img.transpose(Image.FLIP_TOP_BOTTOM)

    def release(self) -> None:
        for obj in (self.fbo, self._color):
            try:
                obj.release()
            except Exception:
                pass
        try:
            self.ctx.release()
        except Exception:
            pass
