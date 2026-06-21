"""Theme loader tests: schema-1 manifest parsing, glob fallback, focal coercion,
missing-file dropping. Uses zero-byte image files (loader only checks existence,
not decodability)."""

import json
from pathlib import Path

from core.theme import load_theme


def _touch(p: Path) -> None:
    p.write_bytes(b"")


def test_glob_fallback_sorted(tmp_path: Path):
    _touch(tmp_path / "b.jpg")
    _touch(tmp_path / "a.png")
    _touch(tmp_path / "c.webp")
    _touch(tmp_path / "notes.txt")  # ignored: not an image extension
    theme = load_theme(tmp_path)
    names = [Path(i.file).name for i in theme.images]
    assert names == ["a.png", "b.jpg", "c.webp"]
    assert theme.name == tmp_path.name


def test_manifest_images_take_precedence_and_parse_focal(tmp_path: Path):
    _touch(tmp_path / "hero.jpg")
    _touch(tmp_path / "ignored.png")
    (tmp_path / "theme.json").write_text(
        json.dumps({
            "schema": 1,
            "name": "MyPack",
            "version": "2",
            "author": "me",
            "images": [
                {"file": "hero.jpg", "title": "Hero", "credit": "C", "focal": [0.25, 0.75]},
            ],
        }),
        encoding="utf-8",
    )
    theme = load_theme(tmp_path)
    assert theme.name == "MyPack"
    assert theme.version == "2"
    assert len(theme.images) == 1  # globbed 'ignored.png' NOT included
    img = theme.images[0]
    assert img.title == "Hero"
    assert img.focal == (0.25, 0.75)


def test_missing_files_dropped(tmp_path: Path):
    (tmp_path / "theme.json").write_text(
        json.dumps({"schema": 1, "name": "x", "images": [{"file": "gone.jpg"}]}),
        encoding="utf-8",
    )
    theme = load_theme(tmp_path)
    assert theme.images == []
    assert not theme  # __bool__ is False with no images


def test_corrupt_manifest_falls_back_to_glob(tmp_path: Path):
    _touch(tmp_path / "pic.jpg")
    (tmp_path / "theme.json").write_text("{ not valid json", encoding="utf-8")
    theme = load_theme(tmp_path)
    assert [Path(i.file).name for i in theme.images] == ["pic.jpg"]


def test_glob_recurses_subfolders_and_excludes_favorites(tmp_path: Path):
    _touch(tmp_path / "a.jpg")
    sub = tmp_path / "100_FUJI"
    sub.mkdir()
    _touch(sub / "b.png")
    deep = sub / "more"
    deep.mkdir()
    _touch(deep / "c.raf")                      # RAW, nested two levels
    fav = tmp_path / "Favorites"                # our thumbnails must be excluded
    fav.mkdir()
    _touch(fav / "a_thumb.jpg")
    hidden = tmp_path / ".cache"                # hidden dirs skipped
    hidden.mkdir()
    _touch(hidden / "junk.jpg")

    theme = load_theme(tmp_path)
    names = sorted(Path(i.file).name for i in theme.images)
    assert names == ["a.jpg", "b.png", "c.raf"]


def test_focal_out_of_range_clamped(tmp_path: Path):
    _touch(tmp_path / "p.jpg")
    (tmp_path / "theme.json").write_text(
        json.dumps({"schema": 1, "name": "x",
                    "images": [{"file": "p.jpg", "focal": [9, -3]}]}),
        encoding="utf-8",
    )
    theme = load_theme(tmp_path)
    assert theme.images[0].focal == (1.0, 0.0)
