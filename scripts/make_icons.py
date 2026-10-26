"""Generate the full Tauri v2 icon set for IP Checker.

Produces every path declared in tauri.conf.json -> bundle.icon, plus the
Windows .ico and the macOS / iOS / Android asset variants that `cargo tauri
icon` would normally create. Written as a plain Pillow script so the build
does not depend on an external 1024px source image being present.

Usage:
    python scripts/make_icons.py [--out src-tauri/icons]
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

from PIL import Image, ImageDraw

# Design tokens (kept in sync with src/styles/tokens.css, spec §3.1).
BG = (5, 8, 16, 255)          # #050810
PANEL = (10, 15, 30, 255)     # #0A0F1E
BORDER = (27, 42, 74, 255)    # #1B2A4A
CYAN = (0, 240, 255, 255)     # #00F0FF
TEXT = (230, 241, 255, 255)   # #E6F1FF
MUTED = (139, 155, 180, 255)  # #8B9BB4

MASTER = 1024


def _rounded_mask(size: int, radius_ratio: float = 0.22) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    radius = int(size * radius_ratio)
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def render_master() -> Image.Image:
    """Draw the app icon: a cyan radar sweep over a grid, with a bold 'IP' glyph."""
    s = MASTER
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Panel background, clipped to a rounded square.
    panel = Image.new("RGBA", (s, s), BG)
    pdraw = ImageDraw.Draw(panel)

    # Grid lines (the same faint grid used behind the UI).
    step = s // 12
    for i in range(step, s, step):
        pdraw.line([(i, 0), (i, s)], fill=(27, 42, 74, 110), width=max(1, s // 340))
        pdraw.line([(0, i), (s, i)], fill=(27, 42, 74, 110), width=max(1, s // 340))
    img.paste(panel, (0, 0), _rounded_mask(s))

    # Radar rings.
    cx, cy = s // 2, s // 2
    for r in (int(s * 0.30), int(s * 0.22), int(s * 0.14)):
        draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=(0, 240, 255, 70), width=max(2, s // 200))

    # Radar sweep wedge (a filled arc, brightest at the leading edge).
    sweep = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    sdraw = ImageDraw.Draw(sweep)
    rad = int(s * 0.30)
    sdraw.pieslice((cx - rad, cy - rad, cx + rad, cy + rad), start=-70, end=-10, fill=(0, 240, 255, 46))
    sdraw.line(
        [(cx, cy), (cx + rad * math.cos(math.radians(-10)), cy + rad * math.sin(math.radians(-10)))],
        fill=CYAN,
        width=max(3, s // 128),
    )
    img.alpha_composite(sweep)

    # Outer border.
    draw.rounded_rectangle(
        (2, 2, s - 3, s - 3),
        radius=int(s * 0.22),
        outline=BORDER,
        width=max(2, s // 170),
    )

    # Centre core dot.
    core = int(s * 0.028)
    draw.ellipse((cx - core, cy - core, cx + core, cy + core), fill=CYAN)

    # 'IP' wordmark below the centre, bold and high-contrast (legible at 32px).
    bar_w = max(4, int(s * 0.055))
    top = int(s * 0.60)
    height = int(s * 0.20)
    left = int(s * 0.30)
    # I
    draw.rectangle((left, top, left + bar_w, top + height), fill=TEXT)
    # P
    px = left + bar_w + int(s * 0.055)
    stem_w = bar_w
    draw.rectangle((px, top, px + stem_w, top + height), fill=TEXT)
    bowl_w = int(s * 0.125)
    bowl_h = int(height * 0.56)
    draw.rectangle((px + stem_w, top, px + stem_w + bowl_w, top + bowl_h), fill=TEXT)
    draw.rectangle(
        (px + stem_w + bowl_w - stem_w, top + bowl_h - stem_w, px + stem_w + bowl_w, top + bowl_h),
        fill=TEXT,
    )
    # Punch the bowl's counter so it reads as a letter, not a block.
    hole_pad = max(2, stem_w // 2)
    draw.rectangle(
        (px + stem_w + hole_pad, top + hole_pad, px + stem_w + bowl_w - stem_w, top + bowl_h - hole_pad),
        fill=PANEL,
    )

    # Small cyan status ticks in the lower third (the "signal" motif).
    tick_y = top + height + int(s * 0.055)
    tick_h = max(3, int(s * 0.018))
    tx = int(s * 0.30)
    for i, w in enumerate((0.055, 0.035, 0.045, 0.030, 0.050)):
        draw.rectangle((tx, tick_y, tx + int(s * w), tick_y + tick_h), fill=CYAN if i % 2 == 0 else MUTED)
        tx += int(s * w) + int(s * 0.018)

    return img


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the Tauri v2 icon set.")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parent.parent / "src-tauri" / "icons"),
        help="Output directory (default: src-tauri/icons).",
    )
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    master = render_master()
    master.save(out / "icon.png")

    # PNG sizes referenced by tauri.conf.json plus the standard Tauri set.
    png_sizes = {
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon-512.png": 512,
        "Square30x30Logo.png": 30,
        "Square44x44Logo.png": 44,
        "Square71x71Logo.png": 71,
        "Square89x89Logo.png": 89,
        "Square107x107Logo.png": 107,
        "Square142x142Logo.png": 142,
        "Square150x150Logo.png": 150,
        "Square284x284Logo.png": 284,
        "Square310x310Logo.png": 310,
        "StoreLogo.png": 50,
    }
    for name, size in png_sizes.items():
        master.resize((size, size), Image.LANCZOS).save(out / name)

    # Windows .ico: multi-resolution so the installer and taskbar both look right.
    master.save(
        out / "icon.ico",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    # macOS .icns (Tauri expects it if a mac target is ever added).
    try:
        master.save(out / "icon.icns")
    except (ValueError, OSError):
        pass

    # iOS / Android variants: Tauri looks for icons/ios/** and icons/android/**.
    ios_dir = out / "ios"
    ios_dir.mkdir(exist_ok=True)
    for name, size in {
        "AppIcon-20x20@1x.png": 20,
        "AppIcon-20x20@2x.png": 40,
        "AppIcon-20x20@3x.png": 60,
        "AppIcon-29x29@1x.png": 29,
        "AppIcon-29x29@2x.png": 58,
        "AppIcon-29x29@3x.png": 87,
        "AppIcon-40x40@1x.png": 40,
        "AppIcon-40x40@2x.png": 80,
        "AppIcon-40x40@3x.png": 120,
        "AppIcon-60x60@2x.png": 120,
        "AppIcon-60x60@3x.png": 180,
        "AppIcon-76x76@1x.png": 76,
        "AppIcon-76x76@2x.png": 152,
        "AppIcon-83.5x83.5@2x.png": 167,
        "AppIcon-1024x1024@1x.png": 1024,
    }.items():
        master.resize((size, size), Image.LANCZOS).save(ios_dir / name)

    android_dir = out / "android"
    android_dir.mkdir(exist_ok=True)
    for folder, size in {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
    }.items():
        d = android_dir / folder
        d.mkdir(exist_ok=True)
        master.resize((size, size), Image.LANCZOS).save(d / "ic_launcher.png")
        master.resize((size, size), Image.LANCZOS).save(d / "ic_launcher_round.png")
        master.resize((size, size), Image.LANCZOS).save(d / "ic_launcher_foreground.png")

    written = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    print(f"wrote {len(written)} files into {out}")
    for name in written:
        print(f"  {name}")


if __name__ == "__main__":
    main()
