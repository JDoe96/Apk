#!/usr/bin/env python3
"""Firekirin 3.0 - asset pipeline: builds all icon/UI images from generated art."""
from PIL import Image, ImageDraw, ImageFilter, ImageEnhance
import os

ART = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(os.path.dirname(ART), 'res')
ASSETS = os.path.join(os.path.dirname(ART), 'assets')

# ---------- helpers ----------
def luminance_to_alpha(im, floor=28, boost=1.25):
    """Gold-on-black -> transparent background. alpha = clamp(max(rgb) * boost)."""
    r, g, b, a = im.convert('RGBA').split()
    mx = ImageChops_max(r, g, b)
    mx = mx.point(lambda v: int(min(255, max(0, (v - floor) * boost))))
    a = ImageChops_min(a, mx)
    return Image.merge('RGBA', (r, g, b, a))

def ImageChops_max(*ims):
    out = ims[0]
    for im in ims[1:]:
        out = ImageChops_lighter(out, im)
    return out

def ImageChops_lighter(a, b):
    return Image.eval(Image.merge('RGB', (a, b, b)).convert('L') if False else a, lambda v: v)  # placeholder
# use PIL built-ins instead
from PIL import ImageChops

def key_out_black(im, floor=26):
    r, g, b, a = im.convert('RGBA').split()
    mx = ImageChops.lighter(ImageChops.lighter(r, g), b)
    alpha = mx.point(lambda v: 0 if v <= floor else min(255, int((v - floor) * 1.35)))
    alpha = alpha.filter(ImageFilter.GaussianBlur(0.6))
    a2 = ImageChops.multiply(a, alpha)
    return Image.merge('RGBA', (r, g, b, a2))

def fit_center(src, size, scale=1.0, bg=None):
    """Fit src (RGBA) centered into size with given scale; optional bg color fill."""
    im = src
    tw, th = size
    # scale so that max dimension * scale fits
    s = min(tw, th) * scale / max(im.size)
    im = im.resize((max(1, int(im.width * s)), max(1, int(im.height * s))), Image.LANCZOS)
    canvas = Image.new('RGBA', size, bg or (0, 0, 0, 0))
    canvas.paste(im, ((tw - im.width) // 2, (th - im.height) // 2), im)
    return canvas

def circle_badge(im, size, ring=True):
    """Place image inside a black circle with a gold ring on transparent canvas."""
    canvas = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    mask = Image.new('L', (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.ellipse([2, 2, size - 3, size - 3], fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(1.0))
    black = Image.new('RGBA', (size, size), (6, 4, 2, 255))
    canvas.paste(black, (0, 0), mask)
    if ring:
        ring_im = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        rd = ImageDraw.Draw(ring_im)
        rw = max(2, size // 48)
        rd.ellipse([2 + rw, 2 + rw, size - 3 - rw, size - 3 - rw], outline=(248, 196, 56, 220), width=rw)
        ring_im = ring_im.filter(ImageFilter.GaussianBlur(0.4))
        canvas.alpha_composite(ring_im)
    # emblem at ~72% of inner circle
    emblem = fit_center(im, (size, size), scale=0.72)
    inner = Image.new('L', (size, size), 0)
    di = ImageDraw.Draw(inner)
    di.ellipse([size * 0.09, size * 0.09, size * 0.91, size * 0.91], fill=255)
    inner = inner.filter(ImageFilter.GaussianBlur(1.2))
    canvas.paste(emblem, (0, 0), ImageChops.multiply(emblem.split()[3].point(lambda v: v), inner) if False else None)
    # paste emblem masked by inner circle
    emblem_a = emblem.split()[3]
    merged = ImageChops.multiply(emblem_a, inner)
    canvas.paste(emblem, (0, 0), merged)
    return canvas

def radial_bg(size, color=(248, 196, 56)):
    """Dark background with a subtle gold radial glow."""
    im = Image.new('RGB', (size, size), (4, 3, 2))
    glow = Image.new('L', (size, size), 0)
    d = ImageDraw.Draw(glow)
    cx = cy = size // 2
    r = size // 2
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=255)
    glow = glow.filter(ImageFilter.GaussianBlur(size // 8))
    glow = glow.point(lambda v: int(v * 0.32))
    gold = Image.new('RGB', (size, size), color)
    im = Image.composite(gold, im, glow)
    return im.convert('RGBA')

# ---------- load art ----------
emblem = Image.open(os.path.join(ART, 'emblem_master.png')).convert('RGBA')
flame = Image.open(os.path.join(ART, 'flame_square.png')).convert('RGBA')
chip = Image.open(os.path.join(ART, 'chip_square.png')).convert('RGBA')

emblem = key_out_black(emblem)
flame = key_out_black(flame)
chip = key_out_black(chip)

# ---------- 1) launcher icons (legacy raster, circular badge) ----------
launcher_sizes = {48: 'u3.png', 72: 'SD.png', 96: 'jy.png', 144: 'D2.png', 192: 'CG.png'}
for size, fname in launcher_sizes.items():
    icon = circle_badge(emblem, size)
    icon.save(os.path.join(RES, fname))
    print('icon', size, fname)

# ---------- 2) round icons ----------
round_sizes = {48: '7c.png', 72: 'tf.png', 96: '1S.png', 144: '5Q.png', 192: 'C9.png'}
for size, fname in round_sizes.items():
    icon = circle_badge(emblem, size, ring=True)
    icon.save(os.path.join(RES, fname))
    print('round', size, fname)

# ---------- 3) adaptive foreground (emblem centered, safe zone) ----------
fg_sizes = {108: '0y.png', 162: 'Mb.png', 216: 'kb.png', 324: '_e.png', 432: 'Et.png'}
for size, fname in fg_sizes.items():
    fg = fit_center(emblem, (size, size), scale=0.58)
    fg.save(os.path.join(RES, fname))
    print('fg', size, fname)

# ---------- 4) adaptive background (dark + gold glow) ----------
bg_sizes = {108: 'cZ.png', 162: 'ik.png', 216: '63.png', 324: 'B1.png', 432: 'DF.png'}
for size, fname in bg_sizes.items():
    bg = radial_bg(size)
    bg.save(os.path.join(RES, fname))
    print('bg', size, fname)

# ---------- 5) game UI: golden flame logo (228x225) ----------
flame_logo = fit_center(flame, (228, 225), scale=0.92)
flame_logo.save(os.path.join(ASSETS, 'assets', 'main', 'native', 'ff',
                             'fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png'))
print('flame logo 228x225')

# ---------- 6) game UI: FK chip (139x143) ----------
chip_img = fit_center(chip, (139, 143), scale=0.94)
chip_img.save(os.path.join(ASSETS, 'assets', 'main', 'native', 'f3',
                           'f30ec3a6-59d0-49e3-8542-119734dc2357.4d3f2.png'))
print('fk chip 139x143')

# ---------- 7) loading atlas recolor: navy skeleton -> gold fire theme ----------
atlas_path = os.path.join(ASSETS, 'assets', 'resources', 'native', '15',
                          '150618f7-d19f-4fda-b4be-bbefd88852d2.7ed3d.png')
atlas = Image.open(atlas_path).convert('RGBA')
r, g, b, a = atlas.split()

def remap(v):
    """luminance -> warm gold ramp (deep amber -> bright gold -> white-gold)"""
    t = v / 255.0
    # darken background: keep very dark pixels near-black with warm tint
    if t < 0.08:
        return (int(6 + t * 40), int(3 + t * 20), int(2 + t * 10))
    # gradient: amber -> gold -> yellow-white
    stops = [(120, 40, 6), (232, 140, 16), (250, 200, 40), (255, 236, 120), (255, 252, 235)]
    pos = min(1.0, max(0.0, (t - 0.08) / 0.92))
    idx = pos * (len(stops) - 1)
    i = min(int(idx), len(stops) - 2)
    f = idx - i
    return tuple(int(stops[i][c] * (1 - f) + stops[i + 1][c] * f) for c in range(3))

lut = [remap(v) for v in range(256)]
new_r = r.point([c[0] for c in lut])
new_g = g.point([c[1] for c in lut])
new_b = b.point([c[2] for c in lut])
new_atlas = Image.merge('RGBA', (new_r, new_g, new_b, a))
# subtle contrast/glow boost
new_atlas = ImageEnhance.Contrast(new_atlas).enhance(1.06)
new_atlas.save(atlas_path)
print('atlas recolored')

# ---------- 8) loading bar strips ----------
bar_path = os.path.join(ASSETS, 'assets', 'resources', 'native', 'b6',
                        'b6bb82b9-3930-4a5e-b1a0-48e6ab52d3e3.f4fb1.png')
bar = Image.open(bar_path).convert('RGBA')
w, h = bar.size
# gold gradient fill (left amber -> right bright gold) preserving alpha
grad = Image.new('RGB', (w, h))
gd = ImageDraw.Draw(grad)
for x in range(w):
    t = x / max(1, w - 1)
    c = (int(232 - 20 * t), int(140 + 90 * t), int(16 + 40 * t))
    gd.line([(x, 0), (x, h)], fill=c)
bar_a = bar.split()[3]
new_bar = Image.merge('RGBA', (*grad.split(), bar_a))
new_bar.save(bar_path)
print('bar recolored', w, h)

# dark strip stays (slightly warm dark)
strip_path = os.path.join(ASSETS, 'assets', 'resources', 'native', 'ef',
                          'ef4bcae7-607d-43ed-8160-17cff8f0db12.0ccc2.png')
strip = Image.open(strip_path).convert('RGBA')
r2, g2, b2, a2 = strip.split()
r2 = r2.point(lambda v: int(v * 0.92))
g2 = g2.point(lambda v: int(v * 0.88))
b2 = b2.point(lambda v: int(v * 0.82))
Image.merge('RGBA', (r2, g2, b2, a2)).save(strip_path)
print('strip done')

print('ALL ART DONE')
