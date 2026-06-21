"""ThemePlayer: image rotation, cover-qualification/skip, and cross-fade timing.

Lives in the render layer because it owns GL textures, but the *policy* (hold,
fade, skip-non-covering, letterbox-if-none-qualify) is small and portable in
spirit. One image -> just holds (micro-shift still runs). Two+ -> cross-fades.
"""

from __future__ import annotations

from dataclasses import dataclass

import moderngl
from PIL import Image

from core.config import Config
from core.geometry import Layout
from core.theme import Theme, ThemeImage
from render.renderer import Placement, build_placement
from render.textures import GLImage, load_image

# Playback phases.
_HOLD = "hold"
_FADE = "fade"


@dataclass
class _Entry:
    image: ThemeImage
    width: int
    height: int
    qualifies: bool  # covers the canvas without upscaling past native


@dataclass
class Frame:
    """What the renderer needs for one frame."""

    plA: Placement
    texA: GLImage
    plB: Placement | None
    texB: GLImage | None
    fade: float


class ThemePlayer:
    def __init__(
        self, ctx: moderngl.Context, theme: Theme, layout: Layout, config: Config
    ) -> None:
        self.ctx = ctx
        self.layout = layout
        self.cfg = config
        self.margin = config.overscan_margin_px

        self._entries = self._scan(theme)
        # Prefer images that cover; letterbox only if NONE qualify.
        qualifying = [e for e in self._entries if e.qualifies]
        self.letterbox = not qualifying
        self.playlist = qualifying if qualifying else self._entries

        self.idx = 0
        self.phase = _HOLD
        self.phase_t = 0.0

        self.curTex: GLImage | None = None
        self.curPl: Placement | None = None
        self.nextTex: GLImage | None = None
        self.nextPl: Placement | None = None

        if self.playlist:
            self.curTex, self.curPl = self._load(self.playlist[self.idx])

    # ---- setup ----------------------------------------------------------

    def _scan(self, theme: Theme) -> list[_Entry]:
        entries: list[_Entry] = []
        for img in theme.images:
            try:
                with Image.open(img.file) as im:
                    w, h = im.size
            except Exception:
                continue  # unreadable -> drop
            pl = build_placement(
                self.layout.canvas_w, self.layout.canvas_h, self.margin, w, h, img.focal
            )
            entries.append(_Entry(image=img, width=w, height=h, qualifies=pl.qualifies))
        return entries

    def _load(self, entry: _Entry) -> tuple[GLImage, Placement]:
        tex = load_image(self.ctx, entry.image.file)
        pl = build_placement(
            self.layout.canvas_w, self.layout.canvas_h, self.margin,
            tex.width, tex.height, entry.image.focal,
        )
        return tex, pl

    @property
    def has_content(self) -> bool:
        return bool(self.playlist) and self.curTex is not None

    # ---- per-frame ------------------------------------------------------

    def update(self, dt: float) -> Frame | None:
        """Advance playback by dt seconds and return the frame to draw."""
        if not self.has_content:
            return None

        single = len(self.playlist) <= 1
        self.phase_t += dt

        if self.phase == _HOLD:
            if not single and self.phase_t >= self.cfg.image_duration_sec:
                # Begin cross-fade to the next image.
                nxt = (self.idx + 1) % len(self.playlist)
                self.nextTex, self.nextPl = self._load(self.playlist[nxt])
                self.phase = _FADE
                self.phase_t = 0.0
        elif self.phase == _FADE:
            dur = self.cfg.crossfade_duration_sec
            if self.phase_t >= dur or dur <= 0.0:
                # Fade complete: next becomes current.
                if self.curTex is not None:
                    self.curTex.release()
                self.curTex, self.curPl = self.nextTex, self.nextPl
                self.nextTex, self.nextPl = None, None
                self.idx = (self.idx + 1) % len(self.playlist)
                self.phase = _HOLD
                self.phase_t = 0.0

        fade = 0.0
        if self.phase == _FADE and self.cfg.crossfade_duration_sec > 0:
            fade = min(1.0, self.phase_t / self.cfg.crossfade_duration_sec)

        return Frame(
            plA=self.curPl, texA=self.curTex,
            plB=self.nextPl, texB=self.nextTex, fade=fade,
        )

    def release(self) -> None:
        for tex in (self.curTex, self.nextTex):
            if tex is not None:
                tex.release()
