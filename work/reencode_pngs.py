#!/usr/bin/env python3
"""
Re-encode replacement PNGs so they match the original APK's PNG
color type / bit depth. Cocos2d-js and some Android decoders can
abort when a texture that was shipped as indexed-color (type 3)
is replaced with a 32-bit RGBA PNG of the same dimensions.
"""
import io
import os
import struct
import zipfile

from PIL import Image

WORK_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(WORK_DIR)
ORIG_ZIP = os.path.join(REPO_ROOT, "firekirin777_2_2.apk.zip")


def png_props(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    w, h = struct.unpack(">II", data[16:24])
    bitd, color, comp, filt, inter = data[24:29]
    return {
        "w": w,
        "h": h,
        "bit": bitd,
        "color": color,
        "inter": inter,
        "len": len(data),
    }


def encode_like_original(new_im: Image.Image, orig_data: bytes) -> bytes:
    props = png_props(orig_data)
    orig = Image.open(io.BytesIO(orig_data))
    # Always keep the replacement pixels, but force the original mode.
    target_w, target_h = orig.size
    im = new_im.convert("RGBA").resize((target_w, target_h), Image.LANCZOS)

    color = props["color"] if props else orig.mode
    bit = props["bit"] if props else 8

    if color == 3 or orig.mode == "P":
        colors = 2 ** max(1, min(bit, 8))
        # Keep transparency when the original had a tRNS / palette alpha.
        quantized = im.quantize(colors=colors, method=Image.FASTOCTREE, dither=Image.NONE)
        buf = io.BytesIO()
        quantized.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    if color == 0 or orig.mode == "L":
        gray = im.convert("L")
        buf = io.BytesIO()
        gray.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    if color == 4 or orig.mode == "LA":
        la = im.convert("LA")
        buf = io.BytesIO()
        la.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    # color 2 (RGB) or 6 (RGBA) — write RGBA/RGB to match
    if color == 2 or orig.mode == "RGB":
        rgb = im.convert("RGB")
        buf = io.BytesIO()
        rgb.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    buf = io.BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


# In-game textures that the loading / start scene actually decodes.
# These MUST match the original PNG color type or the native image
# decoder can abort during the rotating-spinner scene.
GAME_TEXTURES = [
    "assets/assets/main/native/f3/f30ec3a6-59d0-49e3-8542-119734dc2357.4d3f2.png",
    "assets/assets/main/native/ff/fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png",
    "assets/assets/resources/native/15/150618f7-d19f-4fda-b4be-bbefd88852d2.7ed3d.png",
    "assets/assets/resources/native/b6/b6bb82b9-3930-4a5e-b1a0-48e6ab52d3e3.f4fb1.png",
    "assets/assets/resources/native/ef/ef4bcae7-607d-43ed-8160-17cff8f0db12.0ccc2.png",
]

# Launcher / adaptive layers that were originally indexed-color.
# Round-icon 1x1 stubs stay RGBA (we want real icons).
LAUNCHER_INDEXED = [
    "res/63.png",
    "res/B1.png",
    "res/DF.png",
    "res/cZ.png",
    "res/ik.png",
]


def main():
    outer = zipfile.ZipFile(ORIG_ZIP)
    orig = zipfile.ZipFile(io.BytesIO(outer.read("firekirin777_2_2.apk")))

    changed = 0
    for rel in GAME_TEXTURES + LAUNCHER_INDEXED:
        work_path = os.path.join(WORK_DIR, rel)
        if not os.path.exists(work_path):
            print("skip missing", rel)
            continue
        orig_data = orig.read(rel)
        with Image.open(work_path) as im:
            new_data = encode_like_original(im, orig_data)
        before = png_props(open(work_path, "rb").read())
        after = png_props(new_data)
        orig_p = png_props(orig_data)
        with open(work_path, "wb") as f:
            f.write(new_data)
        print(f"{rel}")
        print(f"  orig {orig_p}")
        print(f"  was  {before}")
        print(f"  now  {after}")
        changed += 1
    print(f"re-encoded {changed} PNGs to match original color type")


if __name__ == "__main__":
    main()
