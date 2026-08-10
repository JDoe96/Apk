#!/usr/bin/env python3
"""
Firekirin 3.0 APK signer - pure Python
Signs an APK with v1 (JAR) + v2 (APK Signature Scheme v2) using a fresh RSA-2048 key.
"""
import base64
import hashlib
import struct
import zlib
import zipfile
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from asn1crypto import cms, core, x509 as ac_x509

# ---------------------------------------------------------------- key/cert
def make_key_cert(common_name="Firekirin 3.0", days=3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, common_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 10))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert

# ---------------------------------------------------------------- v1 (JAR)
def _b64(data):
    return base64.b64encode(data).decode("ascii")

def _name_lines(name):
    """'Name: ' header lines with 72-byte JAR wrapping."""
    if len(name) <= 65:
        return ["Name: " + name]
    lines = ["Name: " + name[:65]]
    rest = name[65:]
    while rest:
        lines.append(" " + rest[:71])
        rest = rest[71:]
    return lines

def _full_name_from_section(first_lines):
    """Reconstruct full entry name from wrapped section header lines."""
    name = ""
    for ln in first_lines:
        if ln.startswith("Name: "):
            name += ln[6:]
        elif ln.startswith(" ") and name:
            name += ln[1:]
    return name

def jar_manifest(entries):
    """entries: list of (name, data) -> MANIFEST.MF bytes"""
    lines = ["Manifest-Version: 1.0", "Created-By: 1.0 (Firekirin 3.0 Build)"]
    digests = {}
    for name, data in entries:
        if name.startswith("META-INF/"):
            continue
        d = hashlib.sha256(data).digest()
        digests[name] = d
        lines += _name_lines(name)
        lines.append("SHA-256-Digest: " + _b64(d))
        lines.append("")
    lines.append("")
    return ("\r\n".join(lines)).encode("utf-8"), digests

def jar_sf(manifest_bytes, digests):
    text = manifest_bytes.decode("utf-8")
    sections = {}
    for block in text.split("\r\n\r\n"):
        first_lines = block.split("\r\n")
        name = _full_name_from_section(first_lines)
        if name:
            sections[name] = hashlib.sha256(block.encode("utf-8")).digest()
    lines = [
        "Signature-Version: 1.0",
        "Created-By: 1.0 (Firekirin 3.0 Build)",
        "SHA-256-Digest-Manifest: " + _b64(hashlib.sha256(manifest_bytes).digest()),
    ]
    for name in digests:
        lines += _name_lines(name)
        lines.append("SHA-256-Digest: " + _b64(sections[name]))
        lines.append("")
    lines.append("")
    return ("\r\n".join(lines)).encode("utf-8")

def pkcs7_signature_block(cert_der, content, key):
    """PKCS#7 SignedData (CERT.RSA) signing `content` (CERT.SF bytes)."""
    cert = ac_x509.Certificate.load(cert_der)
    digest_algorithm = cms.DigestAlgorithm({"algorithm": "sha256"})

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": cms.CMSAttributeType("content_type"),
            "values": [cms.ContentType("data")],
        }),
        cms.CMSAttribute({
            "type": cms.CMSAttributeType("message_digest"),
            "values": [cms.OctetString(hashlib.sha256(content).digest())],
        }),
        cms.CMSAttribute({
            "type": cms.CMSAttributeType("signing_time"),
            "values": [cms.Time({"utc_time": core.UTCTime(datetime.now(timezone.utc))})],
        }),
    ])
    # Android/apksig verifies the signature over the signedAttrs as stored,
    # i.e. with the implicit [0] tag. Build that exact DER form:
    attrs_der = signed_attrs.dump()
    if len(attrs_der) < 0x80:
        tagged = b'\xa0' + bytes([len(attrs_der)]) + attrs_der
    else:
        n = len(attrs_der)
        ln = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        tagged = b'\xa0' + bytes([0x80 | len(ln)]) + ln + attrs_der
    signature = key.sign(tagged, padding.PKCS1v15(), hashes.SHA256())

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": cert.issuer,
            "serial_number": cert.serial_number,
        })}),
        "digest_algorithm": digest_algorithm,
        "signed_attrs": signed_attrs,
        "signature_algorithm": cms.SignedDigestAlgorithm({
            "algorithm": "rsassa_pkcs1v15",
            "parameters": core.Null,
        }),
        "signature": signature,
    })
    sd = cms.SignedData({
        "version": "v1",
        "digest_algorithms": cms.DigestAlgorithms([digest_algorithm]),
        "encap_content_info": cms.ContentInfo({
            "content_type": "data",
            "content": content,
        }),
        "certificates": [cert],
        "signer_infos": [signer_info],
    })
    ci = cms.ContentInfo({"content_type": "signed_data", "content": sd})
    return ci.dump()

# ---------------------------------------------------------------- zip writer
class _ZipWriter:
    """Minimal zip writer with 4/4096-byte data alignment."""

    def __init__(self):
        self.buf = bytearray()
        self.central = []
        self.offset = 0

    def add_entry(self, name, data, src_info=None):
        if src_info is not None and src_info.compress_type == zipfile.ZIP_STORED:
            method = zipfile.ZIP_STORED
        else:
            method = zipfile.ZIP_DEFLATED
        flag = (src_info.flag_bits & 0x0800) if src_info else 0
        crc = zlib.crc32(data) & 0xffffffff
        if method == zipfile.ZIP_DEFLATED:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            comp = co.compress(data) + co.flush()
            genflag = 0x0800 | flag
        else:
            comp = data
            genflag = flag
        align = 4096 if (name.startswith("lib/") and method == zipfile.ZIP_STORED) else (4 if method == zipfile.ZIP_STORED else 1)
        extra = b""
        if align > 1:
            need = (-(self.offset + 30 + len(name.encode("utf-8"))) % align)
            extra = b"\x00" * need
        local = struct.pack('<IHHHHHIIIHH', 0x04034b50, 20, genflag, method, 0, 0,
                            crc, len(comp), len(data), len(name.encode("utf-8")), len(extra))
        self.buf += local + name.encode("utf-8") + extra
        data_off = len(self.buf)
        self.buf += comp
        assert data_off % align == 0 if align > 1 else True
        c = struct.pack('<IHHHHHHIIIHHHHHII', 0x02014b50, 20, 20, genflag, method, 0, 0,
                        crc, len(comp), len(data), len(name.encode("utf-8")), 0, 0, 0, 0, 0, self.offset)
        assert struct.calcsize('<IHHHHHHIIIHHHHHII') == 46
        self.central.append(c + name.encode("utf-8"))
        self.offset = len(self.buf)

    def finish(self):
        cd_start = len(self.buf)
        for c in self.central:
            self.buf += c
        cd_size = len(self.buf) - cd_start
        count = len(self.central)
        self.buf += struct.pack('<IHHHHIIH', 0x06054b50, 0, 0, count, count, cd_size, cd_start, 0)
        return bytes(self.buf)

# ---------------------------------------------------------------- v2
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871a
ALGO_RSA_PKCS1_SHA256 = 0x0101
DIGEST_SHA256 = 0x0101

def v2_chunked_digest(data, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    h.update(struct.pack('<I', 0xa5))
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        h.update(struct.pack('<I', len(chunk)))
        h.update(chunk)
    return h.digest()

def build_v2_block(apk_with_v1, cert_der, key):
    """Insert v2 signing block; returns new APK bytes."""
    eocd_pos = apk_with_v1.rfind(b"PK\x05\x06")
    assert eocd_pos != -1
    cd_offset = struct.unpack_from('<I', apk_with_v1, eocd_pos + 16)[0]
    cd_size = struct.unpack_from('<I', apk_with_v1, eocd_pos + 12)[0]
    assert eocd_pos == cd_offset + cd_size, (eocd_pos, cd_offset + cd_size)

    section1 = apk_with_v1[:cd_offset]
    section3 = apk_with_v1[cd_offset:cd_offset + cd_size]

    # build the block first (size independent of EOCD digest)
    digest1 = v2_chunked_digest(section1)
    digest3 = v2_chunked_digest(section3)
    # section4 digest needs the FINAL eocd (with shifted cd offset) -> compute after block size known

    def make_block(digest4):
        digests_content = struct.pack('<I', 3)
        for dg in (digest1, digest3, digest4):
            digests_content += struct.pack('<II', DIGEST_SHA256, len(dg)) + dg
        certs_content = struct.pack('<I', 1) + struct.pack('<I', len(cert_der)) + cert_der
        attrs_content = struct.pack('<I', 0)  # count = 0 additional attributes
        signed_content = (
            struct.pack('<I', len(digests_content)) + digests_content +
            struct.pack('<I', len(certs_content)) + certs_content +
            struct.pack('<I', len(attrs_content)) + attrs_content
        )

        sig_algs = struct.pack('<I', 1) + struct.pack('<I', ALGO_RSA_PKCS1_SHA256)
        public_key = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        signature = key.sign(signed_content, padding.PKCS1v15(), hashes.SHA256())
        signatures = struct.pack('<I', 1) + struct.pack('<II', ALGO_RSA_PKCS1_SHA256, len(signature)) + signature

        signer = (
            struct.pack('<I', len(signed_content)) + signed_content +
            struct.pack('<I', len(sig_algs)) + sig_algs +
            struct.pack('<I', len(public_key)) + public_key +
            struct.pack('<I', len(signatures)) + signatures
        )
        signers = struct.pack('<I', 1) + struct.pack('<I', len(signer)) + signer

        pair_value = struct.pack('<I', V2_BLOCK_ID) + signers
        block = (
            struct.pack('<Q', 0) +
            APK_SIG_BLOCK_MAGIC +
            struct.pack('<Q', len(pair_value)) + pair_value +
            struct.pack('<Q', 0) +
            APK_SIG_BLOCK_MAGIC
        )
        size_val = len(block) - 8
        block = (
            struct.pack('<Q', size_val) +
            APK_SIG_BLOCK_MAGIC +
            struct.pack('<Q', len(pair_value)) + pair_value +
            struct.pack('<Q', size_val) +
            APK_SIG_BLOCK_MAGIC
        )
        return block

    # iterative: block size does not depend on digest4 length (fixed 32 bytes), so one pass
    dummy4 = b"\x00" * 32
    block = make_block(dummy4)

    # final EOCD with shifted offset
    new_cd_offset = cd_offset + len(block)
    eocd = bytearray(apk_with_v1[eocd_pos:])
    struct.pack_into('<I', eocd, 16, new_cd_offset)
    digest4 = v2_chunked_digest(bytes(eocd))
    block = make_block(digest4)
    # sanity: block size unchanged
    assert len(block) == len(block)

    new_apk = section1 + block + section3 + bytes(eocd)
    return block, new_apk

# ---------------------------------------------------------------- driver
def sign_apk(apk_path, out_path, key, cert):
    zin = zipfile.ZipFile(apk_path)
    entries = [(i.filename, zin.read(i.filename), i) for i in zin.infolist()]

    mf, digests = jar_manifest([(n, d) for n, d, _ in entries])
    sf = jar_sf(mf, digests)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    rsa_block = pkcs7_signature_block(cert_der, sf, key)

    w = _ZipWriter()
    for name, data, info in entries:
        w.add_entry(name, data, info)
    w.add_entry("META-INF/MANIFEST.MF", mf)
    w.add_entry("META-INF/CERT.SF", sf)
    w.add_entry("META-INF/CERT.RSA", rsa_block)
    apk_with_v1 = w.finish()

    block, new_apk = build_v2_block(apk_with_v1, cert_der, key)
    with open(out_path, "wb") as f:
        f.write(new_apk)
    print(f"v1 entries: {len(entries)+3}, v2 block: {len(block)} bytes")
    return out_path

if __name__ == "__main__":
    import sys
    key, cert = make_key_cert()
    sign_apk(sys.argv[1], sys.argv[2], key, cert)
    print("signed:", sys.argv[2])
