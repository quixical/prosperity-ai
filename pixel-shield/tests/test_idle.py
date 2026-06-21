"""Smoke tests for the Linux activity probes — they call live X11/PipeWire/D-Bus
interfaces, so we only assert they return safe, well-typed values without
crashing (actual values depend on the live session state)."""

from platform_linux import idle


def test_get_idle_ms_nonnegative():
    assert idle.get_idle_ms() >= 0


def test_is_fullscreen_busy_returns_bool():
    assert isinstance(idle.is_fullscreen_busy(), bool)


def test_audio_active_returns_bool():
    assert isinstance(idle.audio_active(), bool)


def test_screensaver_inhibited_returns_bool():
    assert isinstance(idle.screensaver_inhibited(), bool)


def test_media_active_returns_bool():
    assert isinstance(idle.media_active(), bool)
