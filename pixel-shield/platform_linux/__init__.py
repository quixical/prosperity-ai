"""Linux-specific glue: paths, monitors (XRandR), idle (XScreenSaver), media
detection (PipeWire/D-Bus), the X11 desktop-window wallpaper host, favorites
(symlink), autostart (XDG). The portable `core` imports nothing from here.

This is the Linux sibling of the Windows build's `platform_linux`; both expose the
same module surface so `modes`/`render` are identical apart from the import name.
"""
