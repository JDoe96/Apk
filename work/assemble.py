#!/usr/bin/env python3
"""Assemble Firekirin 3.0 APK from the original, replacing modified entries."""
import hashlib
import os
import sys
import zipfile

ORIG = sys.argv[1] if len(sys.argv) > 1 else 'extracted/firekirin777_2_2.apk'
OUT_UNSIGNED = sys.argv[2] if len(sys.argv) > 2 else 'work/Firekirin3.0-unsigned.apk'
WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# files that were modified (path in zip -> workspace file)
MODIFIED = {
    'AndroidManifest.xml': os.path.join(WORK, 'AndroidManifest.xml'),
    'resources.arsc': os.path.join(WORK, 'resources.arsc'),
    'res/u3.png': os.path.join(WORK, 'res/u3.png'),
    'res/SD.png': os.path.join(WORK, 'res/SD.png'),
    'res/jy.png': os.path.join(WORK, 'res/jy.png'),
    'res/D2.png': os.path.join(WORK, 'res/D2.png'),
    'res/CG.png': os.path.join(WORK, 'res/CG.png'),
    'res/7c.png': os.path.join(WORK, 'res/7c.png'),
    'res/tf.png': os.path.join(WORK, 'res/tf.png'),
    'res/1S.png': os.path.join(WORK, 'res/1S.png'),
    'res/5Q.png': os.path.join(WORK, 'res/5Q.png'),
    'res/C9.png': os.path.join(WORK, 'res/C9.png'),
    'res/0y.png': os.path.join(WORK, 'res/0y.png'),
    'res/Mb.png': os.path.join(WORK, 'res/Mb.png'),
    'res/kb.png': os.path.join(WORK, 'res/kb.png'),
    'res/_e.png': os.path.join(WORK, 'res/_e.png'),
    'res/Et.png': os.path.join(WORK, 'res/Et.png'),
    'res/cZ.png': os.path.join(WORK, 'res/cZ.png'),
    'res/ik.png': os.path.join(WORK, 'res/ik.png'),
    'res/63.png': os.path.join(WORK, 'res/63.png'),
    'res/B1.png': os.path.join(WORK, 'res/B1.png'),
    'res/DF.png': os.path.join(WORK, 'res/DF.png'),
    'assets/assets/main/native/ff/fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png': os.path.join(WORK, 'assets/assets/main/native/ff/fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png'),
    'assets/assets/main/native/f3/f30ec3a6-59d0-49e3-8542-119734dc2357.4d3f2.png': os.path.join(WORK, 'assets/assets/main/native/f3/f30ec3a6-59d0-49e3-8542-119734dc2357.4d3f2.png'),
    'assets/assets/resources/native/15/150618f7-d19f-4fda-b4be-bbefd88852d2.7ed3d.png': os.path.join(WORK, 'assets/assets/resources/native/15/150618f7-d19f-4fda-b4be-bbefd88852d2.7ed3d.png'),
    'assets/assets/resources/native/b6/b6bb82b9-3930-4a5e-b1a0-48e6ab52d3e3.f4fb1.png': os.path.join(WORK, 'assets/assets/resources/native/b6/b6bb82b9-3930-4a5e-b1a0-48e6ab52d3e3.f4fb1.png'),
    'assets/assets/resources/native/ef/ef4bcae7-607d-43ed-8160-17cff8f0db12.0ccc2.png': os.path.join(WORK, 'assets/assets/resources/native/ef/ef4bcae7-607d-43ed-8160-17cff8f0db12.0ccc2.png'),
}

# use the signer's zip writer for aligned output
sys.path.insert(0, WORK)
from sign import _ZipWriter  # noqa

zin = zipfile.ZipFile(ORIG)
w = _ZipWriter()
checked = set()
for info in zin.infolist():
    name = info.filename
    if name in MODIFIED:
        data = open(MODIFIED[name], 'rb').read()
        checked.add(name)
    else:
        data = zin.read(name)
    w.add_entry(name, data, info)

missing = set(MODIFIED) - checked
if missing:
    print('WARNING: modified files not found in original:', missing)

out = w.finish()
with open(OUT_UNSIGNED, 'wb') as f:
    f.write(out)
print('wrote', OUT_UNSIGNED, len(out), 'bytes')

# verify with zipfile
z = zipfile.ZipFile(OUT_UNSIGNED)
bad = z.testzip()
print('testzip:', bad)
print('entries:', len(z.namelist()))
