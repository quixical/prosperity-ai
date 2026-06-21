"""Pixel Shield (Linux) entry point.

Part 1 (now): the always-on desktop WALLPAPER (figure-8 micro-shift, behind icons).
Part 2 (deferred): the idle SCREENSAVER, reached via the `screensaver` subcommand.

    python main.py                 run the wallpaper (Part 1)
    python main.py --stop          stop a running wallpaper
    python main.py config          open the settings / control panel
    python main.py --install       run the wallpaper at login (XDG autostart)
    python main.py --uninstall     remove run-at-login
    python main.py --status        print wallpaper + autostart status

    python main.py screensaver /s  run the screensaver fullscreen (Part 2)
    python main.py screensaver     open the screensaver config dialog
"""

from __future__ import annotations

import sys

_STOP_ALIASES = ("--stop", "/stop", "stop")
_CONFIG_ALIASES = ("config", "--config", "--settings", "settings")
_INSTALL_ALIASES = ("--install", "/install", "install")
_UNINSTALL_ALIASES = ("--uninstall", "/uninstall", "uninstall")
_STATUS_ALIASES = ("--status", "/status", "status")


def _run_screensaver(args: list[str]) -> int:
    """Part 2 dispatch (wired so the modes stay reachable; build deferred)."""
    from core.config import Config
    from platform_linux import paths

    config = Config.load(paths.config_path())
    saver = args and args[0].strip().lower() in ("/s", "-s", "saver", "run")
    if saver:
        from modes.screensaver import run_screensaver
        return run_screensaver(config)
    from modes.config_dialog import run_config
    return run_config()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)[1:]
    first = args[0].lower() if args else ""

    if first in _STOP_ALIASES:
        from modes.wallpaper import stop_wallpaper
        return stop_wallpaper()

    if first in _CONFIG_ALIASES:
        from modes.config_dialog import run_config
        return run_config()

    if first in _INSTALL_ALIASES:
        from platform_linux import autostart
        print("Run-at-login installed:", autostart.install())
        return 0

    if first in _UNINSTALL_ALIASES:
        from platform_linux import autostart
        autostart.uninstall()
        print("Run-at-login removed.")
        return 0

    if first in _STATUS_ALIASES:
        from platform_linux import autostart, wallpaper_host
        print("Wallpaper running:", wallpaper_host.is_wallpaper_running())
        print("Run-at-login:     ", "installed" if autostart.is_installed() else "not installed")
        return 0

    if first == "screensaver":
        return _run_screensaver(args[1:])

    # Default (Part 1): run the wallpaper.
    from core.config import Config
    from modes.wallpaper import run_wallpaper
    from platform_linux import paths

    config = Config.load(paths.config_path())
    return run_wallpaper(config)


if __name__ == "__main__":
    sys.exit(main())
