#!/bin/bash
# Build pixel-shield_<ver>_amd64.deb — a self-contained package: the app + its
# Python deps bundled via `pip --target` (so it doesn't depend on ~/.local),
# a /usr/bin launcher, a menu entry, the orange icon, and cache-refresh hooks.
#
# Usage:  packaging/build_deb.sh            (run from the project root)
# Output: dist/pixel-shield_<ver>_amd64.deb
set -euo pipefail

VER=1.0.0
HERE="$(cd "$(dirname "$0")/.." && pwd)"          # project root
BUILD="$(mktemp -d)"
ROOT="$BUILD/pixel-shield_$VER"
APP="$ROOT/opt/pixel-shield/app"
LIBS="$ROOT/opt/pixel-shield/libs"
mkdir -p "$APP" "$LIBS" "$ROOT/usr/bin" "$ROOT/usr/share/applications" "$ROOT/DEBIAN"

echo ">> bundling python deps"
python3 -m pip install --target="$LIBS" --quiet --no-compile \
  moderngl pygame Pillow rawpy python-xlib numpy
find "$LIBS" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo ">> copying app"
cp -r "$HERE"/core "$HERE"/render "$HERE"/modes "$HERE"/platform_linux \
      "$HERE"/themes "$HERE"/main.py "$APP"/
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo ">> launcher + menu entry"
cat > "$ROOT/usr/bin/pixel-shield" <<'SH'
#!/bin/sh
export PYTHONPATH="/opt/pixel-shield/libs${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 /opt/pixel-shield/app/main.py "$@"
SH
chmod 0755 "$ROOT/usr/bin/pixel-shield"

cat > "$ROOT/usr/share/applications/pixel-shield.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=Pixel Shield
GenericName=OLED Burn-in Protection
Comment=Micro-shift wallpaper & screensaver — settings and control
Exec=pixel-shield config
Icon=pixel-shield
Terminal=false
Categories=Utility;
StartupNotify=true
Actions=Start;Stop;

[Desktop Action Start]
Name=Start Wallpaper
Exec=pixel-shield

[Desktop Action Stop]
Name=Stop Wallpaper
Exec=pixel-shield --stop
DESK

echo ">> icons"
for s in 16 32 48 64 128 256; do
  d="$ROOT/usr/share/icons/hicolor/${s}x${s}/apps"; mkdir -p "$d"
  convert "$HERE/packaging/pixel-shield-master.png" -resize ${s}x${s} "$d/pixel-shield.png"
done

echo ">> control + maintainer scripts"
SIZE=$(du -sk "$ROOT" | cut -f1)
cat > "$ROOT/DEBIAN/control" <<EOF
Package: pixel-shield
Version: $VER
Section: utils
Priority: optional
Architecture: amd64
Depends: python3 (>= 3.12), python3-tk, libgl1, libglib2.0-bin, x11-xserver-utils, libxss1
Recommends: pulseaudio-utils
Maintainer: quixical <earnestconstruction@gmail.com>
Installed-Size: $SIZE
Description: OLED burn-in protection (micro-shift wallpaper + idle screensaver)
 Pixel Shield protects OLED and high-end displays from burn-in with two parts:
 an always-on wallpaper that drifts the picture ~1px every 10s along a slow
 figure-8, and an idle-triggered fullscreen slideshow with the same gentle drift.
 Supports JPEG/PNG/WebP/TIFF/BMP and camera RAW, multi-monitor, and recursive
 folder scanning. Settings GUI included. X11 / GNOME.
EOF
for s in postinst postrm; do
cat > "$ROOT/DEBIAN/$s" <<'SH'
#!/bin/sh
set -e
gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
update-desktop-database -q >/dev/null 2>&1 || true
exit 0
SH
chmod 0755 "$ROOT/DEBIAN/$s"
done

echo ">> building"
mkdir -p "$HERE/dist"
dpkg-deb --build --root-owner-group "$ROOT" "$HERE/dist/pixel-shield_${VER}_amd64.deb"
rm -rf "$BUILD"
echo ">> done: dist/pixel-shield_${VER}_amd64.deb"
