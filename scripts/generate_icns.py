from __future__ import annotations

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "icons" / "macos-persistence-radar-icon.png"
OUTPUTS = [
    ROOT / "assets" / "icons" / "macos-persistence-radar-icon.icns",
    ROOT / "persistence_radar" / "assets" / "icons" / "macos-persistence-radar-icon.icns",
]


def main() -> int:
    image = Image.open(SOURCE).convert("RGBA")
    sizes = [(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512), (1024, 1024)]
    for output in OUTPUTS:
        output.parent.mkdir(parents=True, exist_ok=True)
        image.save(output, format="ICNS", sizes=sizes)
        print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
