"""Borderless OpenGL window (pygame + moderngl) for the SCREENSAVER overlay.

The wallpaper (Part 1) does NOT use a live GL window: on GNOME/Mutter a client
window has no z-slot between the compositor background and the desktop icons, so
the wallpaper renders offscreen (render.offscreen) and is installed as the desktop
background. The screensaver (Part 2) IS a topmost fullscreen overlay, which the
compositor presents normally - that is what this window provides.

OpenGL 3.3 core; LINEAR filtering + mipmaps for sub-pixel micro-shift smoothness.
"""

from __future__ import annotations

import os

import moderngl
import pygame

from core.geometry import VirtualDesktop

KIND_OVERLAY = "overlay"


class GLWindow:
    """Owns the pygame window + moderngl context. Input is pumped by the caller."""

    def __init__(self, vd: VirtualDesktop, kind: str = KIND_OVERLAY) -> None:
        self.vd = vd
        self.kind = kind
        self.width = vd.width
        self.height = vd.height

        # Place the borderless window at the virtual-desktop origin BEFORE creation
        # (SDL reads this env var at set_mode time). Negative coords are valid.
        os.environ["SDL_VIDEO_WINDOW_POS"] = f"{vd.origin_x},{vd.origin_y}"
        os.environ.setdefault("SDL_VIDEO_ALLOW_SCREENSAVER", "1")

        pygame.init()
        pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MAJOR_VERSION, 3)
        pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MINOR_VERSION, 3)
        pygame.display.gl_set_attribute(
            pygame.GL_CONTEXT_PROFILE_MASK, pygame.GL_CONTEXT_PROFILE_CORE
        )
        pygame.display.gl_set_attribute(pygame.GL_DOUBLEBUFFER, 1)

        flags = pygame.OPENGL | pygame.DOUBLEBUF | pygame.NOFRAME
        self.surface = pygame.display.set_mode((vd.width, vd.height), flags)
        self.hwnd = pygame.display.get_wm_info().get("window")

        self.ctx = moderngl.create_context()

        pygame.display.set_caption("Pixel Shield")
        pygame.mouse.set_visible(False)
        self._make_overlay()

    def _make_overlay(self) -> None:
        """Raise the overlay above everything and grab keyboard focus.

        Forcing focus matters because the screensaver is auto-launched by the
        idle-watch (a background process); without focus the Space-to-favorite key
        would never arrive. Best-effort via EWMH + an input-focus request.
        """
        try:
            from Xlib import X, Xatom, display

            d = display.Display()
            try:
                win = d.create_resource_object("window", self.hwnd)
                state = d.intern_atom("_NET_WM_STATE")
                above = d.intern_atom("_NET_WM_STATE_ABOVE")
                fs = d.intern_atom("_NET_WM_STATE_FULLSCREEN")
                win.change_property(state, Xatom.ATOM, 32, [above, fs])
                win.configure(stack_mode=X.Above)
                win.set_input_focus(X.RevertToParent, X.CurrentTime)
                d.sync()
            finally:
                d.close()
        except Exception:
            pass

    def clear_black(self) -> None:
        """True-black (#000000) clear across the whole window."""
        self.ctx.scissor = None
        self.ctx.clear(0.0, 0.0, 0.0, 1.0)

    def swap(self) -> None:
        pygame.display.flip()

    def close(self) -> None:
        try:
            pygame.mouse.set_visible(True)
        except Exception:
            pass
        pygame.quit()
