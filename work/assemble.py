#!/usr/bin/env python3
"""
Assemble Firekirin 3.0 APK from the original APK, replacing modified entries
and stripping stale signature files.
"""
import io
import os
import sys
import zipfile

WORK_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(WORK_DIR)

ORIG_ZIP = os.path.join(REPO_ROOT, "firekirin777_2_2.apk.zip")
OUT_UNSIGNED = sys.argv[1] if len(sys.argv) > 1 else os.path.join(WORK_DIR, "Firekirin3.0-unsigned.apk")

# Files that were modified (path in zip -> workspace file)
MODIFIED = {
    "AndroidManifest.xml": os.path.join(WORK_DIR, "AndroidManifest.xml"),
    "resources.arsc": os.path.join(WORK_DIR, "resources.arsc"),
    "res/u3.png": os.path.join(WORK_DIR, "res/u3.png"),
    "res/SD.png": os.path.join(WORK_DIR, "res/SD.png"),
    "res/jy.png": os.path.join(WORK_DIR, "res/jy.png"),
    "res/D2.png": os.path.join(WORK_DIR, "res/D2.png"),
    "res/CG.png": os.path.join(WORK_DIR, "res/CG.png"),
    "res/7c.png": os.path.join(WORK_DIR, "res/7c.png"),
    "res/tf.png": os.path.join(WORK_DIR, "res/tf.png"),
    "res/1S.png": os.path.join(WORK_DIR, "res/1S.png"),
    "res/5Q.png": os.path.join(WORK_DIR, "res/5Q.png"),
    "res/C9.png": os.path.join(WORK_DIR, "res/C9.png"),
    "res/0y.png": os.path.join(WORK_DIR, "res/0y.png"),
    "res/Mb.png": os.path.join(WORK_DIR, "res/Mb.png"),
    "res/kb.png": os.path.join(WORK_DIR, "res/kb.png"),
    "res/_e.png": os.path.join(WORK_DIR, "res/_e.png"),
    "res/Et.png": os.path.join(WORK_DIR, "res/Et.png"),
    "res/cZ.png": os.path.join(WORK_DIR, "res/cZ.png"),
    "res/ik.png": os.path.join(WORK_DIR, "res/ik.png"),
    "res/63.png": os.path.join(WORK_DIR, "res/63.png"),
    "res/B1.png": os.path.join(WORK_DIR, "res/B1.png"),
    "res/DF.png": os.path.join(WORK_DIR, "res/DF.png"),
    "assets/assets/main/native/ff/fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png": os.path.join(WORK_DIR, "assets/assets/main/native/ff/fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png"),
    "assets/assets/main/native/f3/f30ec3a6-59d0-49e3-8542-119734dc2357.4d3f2.png": os.path.join(WORK_DIR, "assets/assets/main/native/f3/f30ec3a6-59d0-49e3-8542-119734dc2357.4d3f2.png"),
    "assets/assets/resources/native/15/150618f7-d19f-4fda-b4be-bbefd88852d2.7ed3d.png": os.path.join(WORK_DIR, "assets/assets/resources/native/15/150618f7-d19f-4fda-b4be-bbefd88852d2.7ed3d.png"),
    "assets/assets/resources/native/b6/b6bb82b9-3930-4a5e-b1a0-48e6ab52d3e3.f4fb1.png": os.path.join(WORK_DIR, "assets/assets/resources/native/b6/b6bb82b9-3930-4a5e-b1a0-48e6ab52d3e3.f4fb1.png"),
    "assets/assets/resources/native/ef/ef4bcae7-607d-43ed-8160-17cff8f0db12.0ccc2.png": os.path.join(WORK_DIR, "assets/assets/resources/native/ef/ef4bcae7-607d-43ed-8160-17cff8f0db12.0ccc2.png"),
}

sys.path.insert(0, WORK_DIR)
from sign import ZipWriter

# Read the inner APK from the zip archive
outer_zip = zipfile.ZipFile(ORIG_ZIP)
inner_apk_bytes = outer_zip.read("firekirin777_2_2.apk")
zin = zipfile.ZipFile(io.BytesIO(inner_apk_bytes))

writer = ZipWriter()
checked = set()

# Signature file extensions to strip from original APK
SIG_EXTENSIONS = (".sf", ".rsa", ".dsa", ".ec")

for info in zin.infolist():
    name = info.filename
    # Skip stale signature files in META-INF
    if name.startswith("META-INF/"):
        name_lower = name.lower()
        if name_lower == "meta-inf/manifest.mf" or any(name_lower.endswith(ext) for ext in SIG_EXTENSIONS):
            print(f"Skipping stale signature file: {name}")
            continue

    if name in MODIFIED:
        with open(MODIFIED[name], "rb") as f:
            data = f.read()
        checked.add(name)
        # Modified resources.arsc and PNGs are stored uncompressed
        compress = (name == "AndroidManifest.xml")
    else:
        data = zin.read(name)
        compress = (info.compress_type != zipfile.ZIP_STORED)

    align = 4096 if (name.startswith("lib/") and not compress) else (4 if not compress else 1)
    writer.add_entry(name, data, compress=compress, align=align)

missing = set(MODIFIED) - checked
if missing:
    print("WARNING: modified files not found in original:", missing)

unsigned_apk = writer.finish()
with open(OUT_UNSIGNED, "wb") as f:
    f.write(unsigned_apk)

print(f"Wrote unsigned APK: {OUT_UNSIGNED} ({len(unsigned_apk)} bytes)")
