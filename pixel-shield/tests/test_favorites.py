"""Favorites: Space saves a thumbnail + a symlink to the original into a single
destination folder, de-duplicated, never a full copy."""

from pathlib import Path

from PIL import Image

from platform_linux.favorites import favorite


def _make_image(p: Path, size=(800, 600)):
    Image.new("RGB", size, (120, 60, 200)).save(p, "JPEG")


def test_favorite_writes_thumbnail_and_symlink(tmp_path: Path):
    src = tmp_path / "pic.jpg"
    _make_image(src)
    dest = tmp_path / "Favorites Dest"

    out = favorite(str(src), dest)
    assert out == dest and dest.is_dir()

    # exactly one thumbnail, downscaled (not a full copy)
    thumbs = list(dest.glob("*.thumb.jpg"))
    assert len(thumbs) == 1
    with Image.open(thumbs[0]) as t:
        assert max(t.size) <= 320

    # exactly one symlink, pointing at the original
    links = [p for p in dest.iterdir() if p.is_symlink()]
    assert len(links) == 1
    assert links[0].resolve() == src.resolve()

    # no full-size copy of the original was made
    assert not any(
        p.is_file() and not p.is_symlink()
        and p.stat().st_size == src.stat().st_size
        for p in dest.iterdir()
    )


def test_favorite_is_idempotent(tmp_path: Path):
    src = tmp_path / "pic.jpg"
    _make_image(src)
    dest = tmp_path / "fav"
    favorite(str(src), dest)
    favorite(str(src), dest)
    assert len(list(dest.glob("*.thumb.jpg"))) == 1            # not duplicated
    assert len([p for p in dest.iterdir() if p.is_symlink()]) == 1


def test_favorite_missing_file_returns_none(tmp_path: Path):
    assert favorite(str(tmp_path / "nope.jpg"), tmp_path / "fav") is None
