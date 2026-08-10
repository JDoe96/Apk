#!/usr/bin/env python3
"""
Firekirin 3.0 APK signer
Signs an APK with v1 (JAR Scheme) + v2 (APK Signature Scheme v2)
using standard OpenSSL and Python standard library.
"""
import base64
import hashlib
import io
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

CHUNK_SIZE = 1048576  # 1 MB chunk size for APK Signature Scheme v2
SIG_ALGO_RSA_PKCS1_SHA256 = 0x0103
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A


class ZipWriter:
    """Zip writer with deterministic ordering and 4/4096-byte data alignment."""

    def __init__(self):
        self.buf = bytearray()
        self.central = []
        self.offset = 0

    def add_entry(self, name: str, data: bytes, compress: bool = True, align: int = 1):
        crc = zlib.crc32(data) & 0xFFFFFFFF
        if not compress:
            method = zipfile.ZIP_STORED
            comp = data
            genflag = 0
        else:
            method = zipfile.ZIP_DEFLATED
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            comp = co.compress(data) + co.flush()
            genflag = 0x0800  # UTF-8 filename flag

        name_bytes = name.encode("utf-8")
        extra = b""
        if align > 1:
            # Data starts at: self.offset + 30 + len(name_bytes) + len(extra)
            pad = (-(self.offset + 30 + len(name_bytes))) % align
            extra = b"\x00" * pad

        local_hdr = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            genflag,
            method,
            0,
            0,
            crc,
            len(comp),
            len(data),
            len(name_bytes),
            len(extra),
        )
        local_offset = len(self.buf)
        self.buf += local_hdr + name_bytes + extra
        assert (len(self.buf) % align == 0) if align > 1 else True
        self.buf += comp

        cd_hdr = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            genflag,
            method,
            0,
            0,
            crc,
            len(comp),
            len(data),
            len(name_bytes),
            0,
            0,
            0,
            0,
            0,
            local_offset,
        )
        self.central.append(cd_hdr + name_bytes)
        self.offset = len(self.buf)

    def finish(self) -> bytes:
        cd_start = len(self.buf)
        for c in self.central:
            self.buf += c
        cd_size = len(self.buf) - cd_start
        count = len(self.central)
        eocd = struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, count, count, cd_size, cd_start, 0
        )
        self.buf += eocd
        return bytes(self.buf)


def lp(data: bytes) -> bytes:
    """Little-endian 4-byte uint32 length prefix."""
    return struct.pack("<I", len(data)) + data


def _name_lines(name: str):
    """'Name: ' header line with standard 72-byte line wrapping."""
    if len(name) <= 65:
        return ["Name: " + name]
    lines = ["Name: " + name[:65]]
    rest = name[65:]
    while rest:
        lines.append(" " + rest[:70])
        rest = rest[70:]
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


def make_jar_manifest(entries: list[tuple[str, bytes]]) -> tuple[bytes, dict[str, bytes]]:
    lines = ["Manifest-Version: 1.0", "Created-By: 1.0 (Android SignApk)"]
    digests = {}
    for name, data in entries:
        if name.startswith("META-INF/"):
            continue
        d = hashlib.sha256(data).digest()
        digests[name] = d
        lines += _name_lines(name)
        lines.append("SHA-256-Digest: " + base64.b64encode(d).decode("ascii"))
        lines.append("")
    lines.append("")
    manifest_bytes = ("\r\n".join(lines)).encode("utf-8")
    return manifest_bytes, digests


def make_jar_sf(manifest_bytes: bytes, digests: dict[str, bytes]) -> bytes:
    text = manifest_bytes.decode("utf-8")
    sections = {}
    for block in text.split("\r\n\r\n"):
        first_lines = block.split("\r\n")
        name = _full_name_from_section(first_lines)
        if name:
            sections[name] = hashlib.sha256((block + "\r\n\r\n").encode("utf-8")).digest()

    lines = [
        "Signature-Version: 1.0",
        "Created-By: 1.0 (Android SignApk)",
        "SHA-256-Digest-Manifest: " + base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode("ascii"),
    ]
    for name in digests:
        lines += _name_lines(name)
        sf_digest = sections.get(name, hashlib.sha256(digests[name]).digest())
        lines.append("SHA-256-Digest: " + base64.b64encode(sf_digest).decode("ascii"))
        lines.append("")
    lines.append("")
    return ("\r\n".join(lines)).encode("utf-8")


def generate_key_and_cert(tmpdir: str, common_name: str = "Firekirin 3.0"):
    key_pem = os.path.join(tmpdir, "key.pem")
    cert_pem = os.path.join(tmpdir, "cert.pem")
    cert_der = os.path.join(tmpdir, "cert.der")
    pubkey_der = os.path.join(tmpdir, "pubkey.der")

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_pem,
        "-out", cert_pem, "-days", "10000", "-nodes",
        "-subj", f"/CN={common_name}/O={common_name}/C=US"
    ], capture_output=True, check=True)

    subprocess.run([
        "openssl", "x509", "-in", cert_pem, "-outform", "DER", "-out", cert_der
    ], capture_output=True, check=True)

    subprocess.run([
        "openssl", "rsa", "-in", key_pem, "-pubout", "-outform", "DER", "-out", pubkey_der
    ], capture_output=True, check=True)

    return key_pem, cert_pem, open(cert_der, "rb").read(), open(pubkey_der, "rb").read()


def sign_cms_pkcs7(sf_bytes: bytes, cert_pem: str, key_pem: str, tmpdir: str) -> bytes:
    sf_file = os.path.join(tmpdir, "CERT.SF")
    rsa_file = os.path.join(tmpdir, "CERT.RSA")
    with open(sf_file, "wb") as f:
        f.write(sf_bytes)

    cmd = [
        "openssl", "cms", "-sign", "-in", sf_file, "-signer", cert_pem,
        "-inkey", key_pem, "-outform", "DER", "-out", rsa_file,
        "-nodetach", "-nosmimecap", "-binary", "-md", "sha256"
    ]
    subprocess.run(cmd, capture_output=True, check=True)
    return open(rsa_file, "rb").read()


def rsa_sign_data(data: bytes, key_pem: str, tmpdir: str) -> bytes:
    in_file = os.path.join(tmpdir, "sign_data_in.bin")
    out_file = os.path.join(tmpdir, "sign_data_out.bin")
    with open(in_file, "wb") as f:
        f.write(data)
    subprocess.run([
        "openssl", "dgst", "-sha256", "-sign", key_pem, "-out", out_file, in_file
    ], capture_output=True, check=True)
    return open(out_file, "rb").read()


def compute_v2_root_digest(sec1: bytes, sec3: bytes, eocd_with_signing_block_offset: bytes) -> bytes:
    """Computes Android APK Signature Scheme v2 Merkle root digest over 1MB chunks."""
    chunk_digests = []
    for section in [sec1, sec3, eocd_with_signing_block_offset]:
        offset = 0
        while offset < len(section):
            chunk = section[offset : offset + CHUNK_SIZE]
            prefix = b"\xa5" + struct.pack("<I", len(chunk))
            chunk_digests.append(hashlib.sha256(prefix + chunk).digest())
            offset += len(chunk)
    root_prefix = b"\x5a" + struct.pack("<I", len(chunk_digests))
    return hashlib.sha256(root_prefix + b"".join(chunk_digests)).digest()


def build_v2_signature_block(
    sec1: bytes,
    sec3: bytes,
    original_eocd: bytes,
    cert_der: bytes,
    pubkey_der: bytes,
    key_pem: str,
    tmpdir: str
) -> tuple[bytes, bytes]:
    """Builds the APK Signing Block containing the v2 signature."""
    signing_block_offset = len(sec1)

    # EOCD used for hashing has central directory offset pointing to signing_block_offset
    eocd_for_digest = bytearray(original_eocd)
    struct.pack_into("<I", eocd_for_digest, 16, signing_block_offset)

    root_digest = compute_v2_root_digest(sec1, sec3, bytes(eocd_for_digest))

    # 1. digests: length-prefixed sequence of length-prefixed digest records
    digest_record = struct.pack("<I", SIG_ALGO_RSA_PKCS1_SHA256) + lp(root_digest)
    digests_seq = lp(lp(digest_record))

    # 2. certificates: length-prefixed sequence of length-prefixed X.509 certs
    certs_seq = lp(lp(cert_der))

    # 3. additionalAttributes: length-prefixed sequence (empty)
    attrs_seq = lp(b"")

    # signedData: length-prefixed (digests + certs + attrs)
    signed_data_bytes = digests_seq + certs_seq + attrs_seq

    # Sign signed_data_bytes
    sig_bytes = rsa_sign_data(signed_data_bytes, key_pem, tmpdir)

    # signatures: length-prefixed sequence of length-prefixed signature records
    signature_record = struct.pack("<I", SIG_ALGO_RSA_PKCS1_SHA256) + lp(sig_bytes)
    signatures_seq = lp(lp(signature_record))

    # public key: length-prefixed SPKI DER
    pubkey_seq = lp(pubkey_der)

    # signer: length-prefixed signedData + signatures + publicKey
    signer_bytes = lp(signed_data_bytes) + signatures_seq + pubkey_seq

    # signers: length-prefixed sequence of signer
    signers_seq = lp(lp(signer_bytes))

    # APK Signing Block ID-value pair
    pair_record = (
        struct.pack("<Q", 4 + len(signers_seq))
        + struct.pack("<I", V2_BLOCK_ID)
        + signers_seq
    )

    block_size = len(pair_record) + 24
    signing_block = (
        struct.pack("<Q", block_size)
        + pair_record
        + struct.pack("<Q", block_size)
        + APK_SIG_BLOCK_MAGIC
    )

    # Updated EOCD pointing to central directory at (signing_block_offset + len(signing_block))
    final_eocd = bytearray(original_eocd)
    struct.pack_into("<I", final_eocd, 16, signing_block_offset + len(signing_block))

    return signing_block, bytes(final_eocd)


def sign_apk(unsigned_apk_path: str, output_apk_path: str):
    print(f"Signing APK: {unsigned_apk_path} -> {output_apk_path}")
    zin = zipfile.ZipFile(unsigned_apk_path)

    # Read entries, stripping any existing META-INF signatures
    entries = []
    for info in zin.infolist():
        name = info.filename
        if name.startswith("META-INF/"):
            name_lower = name.lower()
            if name_lower == "meta-inf/manifest.mf" or name_lower.endswith(".sf") or name_lower.endswith(".rsa"):
                continue
        data = zin.read(name)
        compress = (info.compress_type != zipfile.ZIP_STORED)
        align = 4096 if (name.startswith("lib/") and not compress) else (4 if not compress else 1)
        entries.append((name, data, compress, align))

    with tempfile.TemporaryDirectory() as tmpdir:
        key_pem, cert_pem, cert_der, pubkey_der = generate_key_and_cert(tmpdir)

        # 1. JAR Manifest & SF
        mf_bytes, digests = make_jar_manifest([(n, d) for n, d, _, _ in entries])
        sf_bytes = make_jar_sf(mf_bytes, digests)
        rsa_bytes = sign_cms_pkcs7(sf_bytes, cert_pem, key_pem, tmpdir)

        # Build v1 signed zip
        writer = ZipWriter()
        for name, data, compress, align in entries:
            writer.add_entry(name, data, compress=compress, align=align)
        writer.add_entry("META-INF/MANIFEST.MF", mf_bytes, compress=True)
        writer.add_entry("META-INF/CERT.SF", sf_bytes, compress=True)
        writer.add_entry("META-INF/CERT.RSA", rsa_bytes, compress=True)
        apk_v1 = writer.finish()

        # 2. Add APK Signature Scheme v2 block
        eocd_pos = apk_v1.rfind(b"PK\x05\x06")
        assert eocd_pos != -1
        cd_offset = struct.unpack_from("<I", apk_v1, eocd_pos + 16)[0]
        cd_size = struct.unpack_from("<I", apk_v1, eocd_pos + 12)[0]
        assert eocd_pos == cd_offset + cd_size

        sec1 = apk_v1[:cd_offset]
        sec3 = apk_v1[cd_offset : cd_offset + cd_size]
        original_eocd = apk_v1[eocd_pos:]

        signing_block, final_eocd = build_v2_signature_block(
            sec1, sec3, original_eocd, cert_der, pubkey_der, key_pem, tmpdir
        )

        signed_apk = sec1 + signing_block + sec3 + final_eocd

        with open(output_apk_path, "wb") as f:
            f.write(signed_apk)

    print(f"Successfully signed APK ({len(signed_apk)} bytes) -> {output_apk_path}")
    return output_apk_path


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "work/Firekirin3.0-unsigned.apk"
    dst = sys.argv[2] if len(sys.argv) > 2 else "Firekirin3.0.apk"
    sign_apk(src, dst)
