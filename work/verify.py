#!/usr/bin/env python3
"""Independent verification of the signed Firekirin3.0 APK."""
import base64
import hashlib
import struct
import zipfile

import sys
APK = sys.argv[1] if len(sys.argv) > 1 else 'work/Firekirin3.0.apk'

print('=' * 60)
print('1. ZIP integrity')
z = zipfile.ZipFile(APK)
print('  entries:', len(z.namelist()))
print('  testzip:', z.testzip())
infos = z.infolist()
# alignment checks
for i in infos:
    if i.compress_type == zipfile.ZIP_STORED:
        with open(APK, 'rb') as f:
            # find local header via central dir offset
            pass
# read raw file for alignment + v2 checks
data = open(APK, 'rb').read()

print('=' * 60)
print('2. Entry alignment')
for info in infos:
    if info.compress_type == zipfile.ZIP_STORED:
        # locate data: walk local headers
        # use central directory info: header at cd_off
        pass
# simpler: scan local headers
pos = 0
aligned = []
import io
buf = io.BytesIO(data)
for info in infos:
    buf.seek(info.header_offset)
    sig = buf.read(4)
    assert sig == b'PK\x03\x04', (info.filename, info.header_offset)
    buf.seek(info.header_offset + 26)
    nlen, elen = struct.unpack('<HH', buf.read(4))
    data_off = info.header_offset + 30 + nlen + elen
    if info.compress_type == zipfile.ZIP_STORED:
        aligned.append((info.filename, data_off % 4, data_off % 4096 if info.filename.startswith('lib/') else None))
for name, a4, a4k in aligned:
    print(f'  {name}: data%4={a4}' + (f' data%4096={a4k}' if a4k is not None else ''))
    if a4 != 0 or (a4k is not None and a4k != 0):
        print('   !! MISALIGNED')

print('=' * 60)
print('3. v1 (JAR) signature chain')
mf = z.read('META-INF/MANIFEST.MF').decode('utf-8')
sf = z.read('META-INF/CERT.SF')
rsa = z.read('META-INF/CERT.RSA')

# 3a: manifest digests
ok = True
blocks = mf.split('\r\n\r\n')
for b in blocks:
    lines = b.split('\r\n')
    name = ''
    for ln in lines:
        if ln.startswith('Name: '):
            name += ln[6:]
        elif ln.startswith(' ') and name:
            name += ln[1:]
    if not name:
        continue
    digest_line = [l for l in lines if l.startswith('SHA-256-Digest:')]
    if not digest_line:
        ok = False
        print('  !! no digest for', name)
        continue
    expected = base64.b64decode(digest_line[0].split(': ')[1])
    actual = hashlib.sha256(z.read(name)).digest()
    if expected != actual:
        ok = False
        print('  !! digest mismatch:', name)
print('  MANIFEST.MF file digests:', 'OK' if ok else 'FAIL')
# every non-META-INF entry listed?
listed = set()
for b in blocks:
    lines = b.split('\r\n')
    name = ''
    for ln in lines:
        if ln.startswith('Name: '):
            name += ln[6:]
        elif ln.startswith(' ') and name:
            name += ln[1:]
    if name:
        listed.add(name)
missing = [n for n in z.namelist() if not n.startswith('META-INF/') and n not in listed]
print('  entries missing from MANIFEST.MF:', missing if missing else 'none')

# 3b: CERT.SF whole-manifest digest + section digests
sf_text = sf.decode('utf-8')
sf_blocks = sf_text.split('\r\n\r\n')
wm = [l for l in sf_text.split('\r\n') if l.startswith('SHA-256-Digest-Manifest:')]
if wm:
    d = base64.b64decode(wm[0].split(': ')[1])
    print('  SF manifest digest:', 'OK' if d == hashlib.sha256(mf.encode()).digest() else 'FAIL')
# section digests
sec_ok = True
for b in sf_blocks:
    lines = b.split('\r\n')
    name = ''
    for ln in lines:
        if ln.startswith('Name: '):
            name += ln[6:]
        elif ln.startswith(' ') and name:
            name += ln[1:]
    if not name:
        continue
    dl = [l for l in lines if l.startswith('SHA-256-Digest:')]
    # find the manifest section for this name
    for mb in blocks:
        ml = mb.split('\r\n')
        mname = ''
        for ln in ml:
            if ln.startswith('Name: '):
                mname += ln[6:]
            elif ln.startswith(' ') and mname:
                mname += ln[1:]
        if mname == name:
            sec_ok = sec_ok and base64.b64decode(dl[0].split(': ')[1]) == hashlib.sha256(mb.encode()).digest()
            break
print('  SF section digests:', 'OK' if sec_ok else 'FAIL')

# 3c: verify PKCS#7 CERT.RSA with the embedded cert
from asn1crypto import cms as ac_cms
ci = ac_cms.ContentInfo.load(rsa)
sd = ci['content']
si = sd['signer_infos'][0]
signed_attrs = si['signed_attrs']
if getattr(signed_attrs, 'implicit', False):
    signed_attrs = signed_attrs.untag()
cert = sd['certificates'][0].chosen
print('  embedded cert subject:', cert.subject.human_friendly)
# verify signature over signedAttrs
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
pub = load_der_public_key(cert.public_key.dump())
sig = si['signature'].native
# rebuild the implicit [0]-tagged form as stored in the file
attrs_der = signed_attrs.dump()
if len(attrs_der) < 0x80:
    tagged = b'\xa0' + bytes([len(attrs_der)]) + attrs_der
else:
    n = len(attrs_der)
    ln = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    tagged = b'\xa0' + bytes([0x80 | len(ln)]) + ln + attrs_der
try:
    pub.verify(sig, tagged, padding.PKCS1v15(), hashes.SHA256())
    print('  CERT.RSA signature over signedAttrs: OK')
except Exception as e:
    print('  !! signature verify failed:', e)
# check messageDigest attr
for attr in si['signed_attrs']:
    if attr['type'].native == 'message_digest':
        md = attr['values'][0].native
        print('  messageDigest attr matches SF:', 'OK' if md == hashlib.sha256(sf).digest() else 'FAIL')

print('=' * 60)
print('4. v2 (APK Signature Scheme v2)')
# find the signing block: before central directory
eocd_pos = data.rfind(b'PK\x05\x06')
cd_off = struct.unpack_from('<I', data, eocd_pos + 16)[0]
# magic check: last 16 bytes before cd
magic = data[cd_off - 16:cd_off]
print('  block magic at end:', magic)
assert magic == b'APK Sig Block 42'
# trailing size field at cd_off-24..cd_off-16
size_field = struct.unpack_from('<Q', data, cd_off - 24)[0]
block_start = cd_off - size_field - 8
print('  block size:', size_field, 'block start:', block_start)
assert data[block_start:block_start + 8] == struct.pack('<Q', size_field)
assert data[block_start + 8:block_start + 24] == b'APK Sig Block 42'

# walk pairs
p = block_start + 24
pairs = {}
while p < cd_off - 24:
    plen, pid = struct.unpack_from('<QI', data, p)
    pairs[pid] = data[p + 12:p + 12 + plen - 4]
    p += 12 + plen - 4
print('  block pairs ids:', [hex(k) for k in pairs])
v2 = pairs.get(0x7109871a)
assert v2, 'no v2 signer block'

def read_lp(buf, off):
    ln = struct.unpack_from('<I', buf, off)[0]
    return buf[off + 4:off + 4 + ln], off + 4 + ln

signer_count = struct.unpack_from('<I', v2, 0)[0]
print('  signer count:', signer_count)
off = 4
signer_len = struct.unpack_from('<I', v2, off)[0]
off += 4
signed_data, off = read_lp(v2, off)
sig_algs_lp, off = read_lp(v2, off)
pubkey_lp, off = read_lp(v2, off)
signatures_lp, off = read_lp(v2, off)

# digests inside signed_data: [u32 len][u32 count][(u32 algo)(u32 len)(digest)...]
off2 = 0
digests_lp, off2 = read_lp(signed_data, off2)
n = struct.unpack_from('<I', digests_lp, 0)[0]
print('  digests:', n)
offd = 4
for i in range(n):
    algo, dlen = struct.unpack_from('<II', digests_lp, offd)
    dg = digests_lp[offd + 8:offd + 8 + dlen]
    offd += 8 + dlen
    print(f'    algo={algo:#x} digest={dg.hex()[:24]}...')
certs_lp, off2 = read_lp(signed_data, off2)
nc = struct.unpack_from('<I', certs_lp, 0)[0]
print('  certs:', nc)

# verify signature over signed_data (content)
from cryptography.hazmat.primitives.serialization import load_der_public_key
pubk = load_der_public_key(pubkey_lp)
ns = struct.unpack_from('<I', signatures_lp, 0)[0]
off3 = 4
verified = False
for i in range(ns):
    algo, slen = struct.unpack_from('<II', signatures_lp, off3)
    sig = signatures_lp[off3 + 8:off3 + 8 + slen]
    off3 += 8 + slen
    if algo == 0x0101:
        try:
            pubk.verify(sig, signed_data, padding.PKCS1v15(), hashes.SHA256())
            verified = True
            print('  v2 signature (RSA PKCS1v15 SHA256): OK')
        except Exception as e:
            print('  !! v2 sig failed:', e)

# verify content digests by recomputing
def chunked(data, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    h.update(struct.pack('<I', 0xa5))
    for i in range(0, len(data), chunk_size):
        c = data[i:i + chunk_size]
        h.update(struct.pack('<I', len(c)))
        h.update(c)
    return h.digest()

section1 = data[:block_start]
section3 = data[cd_off:eocd_pos]
section4 = data[eocd_pos:]
d1 = chunked(section1)
d3 = chunked(section3)
d4 = chunked(section4)
# compare with digests from signed_data
off2 = 4
computed = []
for i in range(3):
    algo, dlen = struct.unpack_from('<II', digests_lp, off2)
    dg = digests_lp[off2 + 8:off2 + 8 + dlen]
    off2 += 8 + dlen
    computed.append(dg)
print('  content digest 1 (entries):', 'OK' if computed[0] == d1 else 'FAIL')
print('  content digest 3 (central dir):', 'OK' if computed[1] == d3 else 'FAIL')
print('  content digest 4 (EOCD):', 'OK' if computed[2] == d4 else 'FAIL')

print('=' * 60)
print('5. Manifest content')
from pyaxmlparser import APK as PA
a = PA(APK)
print('  package:', a.package)
print('  versionName:', a.version_name)
print('  versionCode:', a.version_code)
print('  application label:', a.application)
print('  main activity:', a.get_main_activity())

print('=' * 60)
print('6. Rebranded assets present')
import os
checks = {
    'app name in arsc': b'Firekirin 3.0' in z.read('resources.arsc'),
}
print('  app name string patched:', checks['app name in arsc'])
print('  icon CG.png size:', len(z.read('res/CG.png')), 'bytes (new)')
print('  flame logo size:', len(z.read('assets/assets/main/native/ff/fffb390e-2dcf-4ca6-91a3-7e645b09ded0.ca676.png')))
print('  checksum files unchanged:', z.read('assets/meta-data/manifest.mf') == open('extracted/firekirin777_2_2.apk', 'rb').read() and True)
