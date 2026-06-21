"""Settings + control panel (tkinter).

Wallpaper section: pictures folder, starting picture, drift cadence, picture fade,
overscan margin, bezel, multi-monitor mode — with a live "pictures advance every ~X
hours" readout. Screensaver section (Part 2, consumed later): its own pictures folder
and the idle minutes before it starts. Plus run-at-login and Start/Stop/Apply.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from core.config import MODE_PRIMARY, MODE_SPAN, Config
from core.microshift import figure8_period
from core.theme import load_theme
from platform_linux import autostart, paths, wallpaper_host

_FIRST = "(first in folder)"


def _folder_images(folder: str) -> list[str]:
    try:
        return [Path(img.file).name for img in load_theme(folder).images]
    except Exception:
        return []


def run_config() -> int:
    cfg = Config.load(paths.config_path())
    wp_dir = str(paths.source_dir(cfg.wallpaper_folder, cfg.theme, cfg.themes_path))
    ss_dir = str(paths.source_dir(cfg.screensaver_folder, cfg.theme, cfg.themes_path))

    root = tk.Tk()
    root.title("Pixel Shield — Settings")
    root.resizable(False, False)
    frm = ttk.Frame(root, padding=16)
    frm.grid(row=0, column=0, sticky="nsew")
    frm.columnconfigure(1, weight=1)

    row = 0

    def label(text: str, **kw) -> int:
        nonlocal row
        ttk.Label(frm, text=text, **kw).grid(row=row, column=0, sticky="w",
                                             pady=4, padx=(0, 12))
        r = row
        row += 1
        return r

    def heading(text: str):
        nonlocal row
        if row:
            ttk.Separator(frm, orient="horizontal").grid(
                row=row, column=0, columnspan=3, sticky="ew", pady=(10, 6))
            row += 1
        ttk.Label(frm, text=text, font=("Segoe UI", 9, "bold")).grid(
            row=row, column=0, columnspan=3, sticky="w", pady=(0, 4))
        row += 1

    # ---- variables -------------------------------------------------------
    wp_folder_var = tk.StringVar(value=wp_dir)
    pic_var = tk.StringVar(value=cfg.wallpaper_image or _FIRST)
    cadence_var = tk.DoubleVar(value=cfg.cadence_sec_per_px)
    fade_var = tk.DoubleVar(value=cfg.wallpaper_fade_sec)
    margin_var = tk.DoubleVar(value=cfg.overscan_margin_px)
    bezel_var = tk.DoubleVar(value=cfg.bezel_width_px)
    mode_var = tk.StringVar(value=cfg.multimonitor_mode)
    ss_folder_var = tk.StringVar(value=ss_dir)
    idle_var = tk.DoubleVar(value=cfg.screensaver_idle_min)
    ss_dur_var = tk.DoubleVar(value=cfg.image_duration_sec)
    ss_fade_var = tk.DoubleVar(value=cfg.crossfade_duration_sec)
    fav_var = tk.StringVar(value=str(paths.favorites_dir(cfg.favorites_folder)))
    autostart_var = tk.BooleanVar(value=autostart.is_installed())

    def folder_row(text: str, var: tk.StringVar):
        r = label(text)
        ttk.Entry(frm, textvariable=var, width=34).grid(row=r, column=1, sticky="ew")

        def browse():
            d = filedialog.askdirectory(initialdir=var.get() or str(Path.home()),
                                        title=text)
            if d:
                var.set(d)
        ttk.Button(frm, text="Browse…", command=browse, width=9).grid(
            row=r, column=2, padx=(8, 0))

    def slider(text, lo, hi, var, fmt="{:.0f}", on_change=None):
        r = label(text)
        vlbl = ttk.Label(frm, width=9)

        def cb(v):
            vlbl.config(text=fmt.format(float(v)))
            if on_change:
                on_change()
        ttk.Scale(frm, from_=lo, to=hi, variable=var, command=cb,
                  length=240).grid(row=r, column=1, sticky="ew")
        vlbl.grid(row=r, column=2, sticky="w", padx=(8, 0))
        cb(var.get())

    # ---- WALLPAPER -------------------------------------------------------
    heading("Wallpaper")
    folder_row("Wallpaper folder", wp_folder_var)

    r = label("Starting picture")
    pic_box = ttk.Combobox(frm, textvariable=pic_var, state="readonly", width=32)
    pic_box.grid(row=r, column=1, columnspan=2, sticky="ew")

    def refresh_pictures(*_):
        names = [_FIRST] + _folder_images(wp_folder_var.get())
        pic_box["values"] = names
        if pic_var.get() not in names:
            pic_var.set(_FIRST)
    wp_folder_var.trace_add("write", refresh_pictures)
    refresh_pictures()

    advance_lbl = ttk.Label(frm, foreground="#0a6")

    def update_advance():
        try:
            hrs = figure8_period(max(0.1, cadence_var.get()), max(1.0, margin_var.get())) / 3600.0
            advance_lbl.config(text=f"Pictures advance about every {hrs:.1f} hours")
        except Exception:
            advance_lbl.config(text="")

    slider("Drift cadence (sec/pixel)", 1, 20, cadence_var, "{:.0f} s", update_advance)
    slider("Picture fade (seconds)", 0, 10, fade_var, "{:.1f} s")
    slider("Overscan margin (px)", 10, 200, margin_var, "{:.0f} px", update_advance)
    slider("Bezel width (px)", 0, 100, bezel_var, "{:.0f} px")
    advance_lbl.grid(row=row, column=0, columnspan=3, sticky="w", pady=(2, 4))
    row += 1
    update_advance()

    r = label("Multi-monitor")
    ttk.Combobox(frm, textvariable=mode_var, values=[MODE_SPAN, MODE_PRIMARY],
                 state="readonly", width=32).grid(row=r, column=1, columnspan=2, sticky="ew")

    # ---- SCREENSAVER (Part 2) -------------------------------------------
    heading("Screensaver  (when idle)")
    folder_row("Screensaver folder", ss_folder_var)
    slider("Start after idle (minutes)", 1, 60, idle_var, "{:.0f} min")
    slider("Seconds per picture", 3, 120, ss_dur_var, "{:.0f} s")
    slider("Picture fade (seconds)", 0, 10, ss_fade_var, "{:.1f} s")
    folder_row("Favorites folder", fav_var)

    # ---- general ---------------------------------------------------------
    heading("General")
    ttk.Checkbutton(frm, text="Start the wallpaper automatically at login",
                    variable=autostart_var).grid(row=row, column=0, columnspan=3,
                                                  sticky="w", pady=(0, 2))
    row += 1

    status = ttk.Label(frm, text="")
    status.grid(row=row, column=0, columnspan=3, sticky="w", pady=(6, 0))
    row += 1

    def set_status(msg: str):
        running = "running" if wallpaper_host.is_wallpaper_running() else "stopped"
        status.config(text=f"Wallpaper: {running}.  {msg}")

    # ---- actions ---------------------------------------------------------
    def collect() -> Config:
        cfg.wallpaper_folder = wp_folder_var.get().strip()
        cfg.wallpaper_image = "" if pic_var.get() == _FIRST else pic_var.get()
        cfg.cadence_sec_per_px = float(cadence_var.get())
        cfg.wallpaper_fade_sec = float(fade_var.get())
        cfg.overscan_margin_px = int(round(margin_var.get()))
        cfg.bezel_width_px = int(round(bezel_var.get()))
        cfg.multimonitor_mode = mode_var.get() if mode_var.get() in (MODE_SPAN, MODE_PRIMARY) else MODE_SPAN
        cfg.screensaver_folder = ss_folder_var.get().strip()
        cfg.screensaver_idle_min = float(idle_var.get())
        cfg.image_duration_sec = float(ss_dur_var.get())
        cfg.crossfade_duration_sec = float(ss_fade_var.get())
        cfg.favorites_folder = fav_var.get().strip()
        cfg.clamp()
        return cfg

    def save():
        collect().save(paths.config_path())
        autostart.set_enabled(autostart_var.get())
        set_status("Saved.")

    def do_start():
        autostart.launch_detached()
        root.after(600, lambda: set_status("Started."))

    def do_stop():
        from modes.wallpaper import stop_wallpaper
        stop_wallpaper()
        root.after(600, lambda: set_status("Stopped."))

    def apply_restart():
        save()
        if wallpaper_host.is_wallpaper_running():
            from modes.wallpaper import stop_wallpaper
            stop_wallpaper()

        def wait_then_start(attempts):
            if not wallpaper_host.is_wallpaper_running() or attempts <= 0:
                autostart.launch_detached()
                root.after(600, lambda: set_status("Applied & restarted."))
            else:
                root.after(150, lambda: wait_then_start(attempts - 1))
        wait_then_start(25)

    btns = ttk.Frame(frm)
    btns.grid(row=row, column=0, columnspan=3, sticky="e", pady=(12, 0))
    ttk.Button(btns, text="Stop", command=do_stop).grid(row=0, column=0, padx=3)
    ttk.Button(btns, text="Start", command=do_start).grid(row=0, column=1, padx=3)
    ttk.Button(btns, text="Save", command=save).grid(row=0, column=2, padx=3)
    ttk.Button(btns, text="Apply & Restart", command=apply_restart).grid(row=0, column=3, padx=3)
    ttk.Button(btns, text="Close", command=root.destroy).grid(row=0, column=4, padx=3)

    set_status("")
    root.update_idletasks()
    root.mainloop()
    return 0
