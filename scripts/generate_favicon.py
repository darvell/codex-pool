#!/usr/bin/env python3
"""Regenerate the favicon with Pillow; not needed for normal builds."""
from pathlib import Path

from PIL import Image

assets = Path(__file__).resolve().parents[1] / "templates" / "assets"
with Image.open(assets / "watering-can.png") as source:
    image = source.convert("RGBA")
    # Ignore near-invisible edge noise when measuring the artwork's bounds.
    bounds = image.getchannel("A").point(lambda alpha: 255 if alpha > 16 else 0).getbbox()
    if bounds is None:
        raise ValueError("Source image is fully transparent")
    image = image.crop(bounds)
    # Keep a small transparent margin and center without distorting the artwork.
    side = max(image.size)
    padding = max(1, round(side * 0.04))
    canvas = Image.new("RGBA", (side + 2 * padding, side + 2 * padding))
    canvas.paste(image, ((canvas.width - image.width) // 2,
                         (canvas.height - image.height) // 2))
    canvas.save(assets / "favicon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
