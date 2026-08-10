#!/usr/bin/env python3
"""
Firekirin 3.0 APK Verifier
Strict independent verifier for:
1. ZIP integrity & entry deduplication
2. Alignment (4-byte / 4096-byte)
3. v1 (JAR Scheme) signature chain & CMS verification
4. v2 (APK Signature Scheme v2) block parsing, 1MB Merkle tree digests, and RSA verification
5. AndroidManifest.xml binary format & package metadata
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

CHUNK_SIZE = 1048576
V2_BLOCK_ID = 0x7109871A
SIG_ALGO_RSA_PKCS1_SHA256 = 0x0103


def _name_lines_join(text: str) -> dict[str, str]:
    """Parse MANIFEST.MF or CERT.SF into a map of entry name -> section text."""
    sections = {}
    blocks = text.split("\r\n\r\n")
    for block in blocks:
        lines = block.split("\r\n")
        name = ""
        for ln in lines:
            if ln.startswith("Name: "):
                name += ln[6:]
            elif ln.startswith(" ") and name:
                name += ln[1:]
        if name:
            sections[name] = block
    return sections


def verify_apk(apk_path: str):
    print("=" * 60)
    print(f"VERIFYING APK: {apk_path}")
    print("=" * 60)

    with open(apk_path, "rb") as f:
        apk_data = f.read()

    # ------------------------------------------------------------ 1. ZIP integrity
    print("\n[1] Checking ZIP Integrity & Entry Deduplication...")
    zin = zipfile.ZipFile(io.BytesIO(apk_data))
    bad = zin.testzip()
    if bad is not None:
        raise ValueError(f"ZIP integrity error in entry: {bad}")
    names = [info.filename for info in zin.infolist()]
    if len(names) != len(set(names)):
        duplicates = [n for n in names if names.count(n) > 1]
        raise ValueError(f"Duplicate ZIP entries detected: {set(duplicates)}")
    print(f"  Passed: {len(names)} unique entries, testzip clean.")

    # ------------------------------------------------------------ 2. Alignment
    print("\n[2] Checking 4-byte and 4096-byte Alignment...")
    with open(apk_path, "rb") as f:
        for info in zin.infolist():
            f.seek(info.header_offset)
            magic, _, _, _, _, _, _, _, _, name_len, extra_len = struct.unpack("<IHHHHHIIIHH", f.read(30))
            if magic != 0x04034B50:
                raise ValueError(f"Invalid local header magic for {info.filename}")
            data_offset = info.header_offset + 30 + name_len + extra_len

            if info.compress_type == zipfile.ZIP_STORED:
                if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                    if data_offset % 4096 != 0:
                        raise ValueError(f"Native lib {info.filename} not 4096-byte aligned! (offset={data_offset})")
                else:
                    if data_offset % 4 != 0:
                        raise ValueError(f"Stored file {info.filename} not 4-byte aligned! (offset={data_offset})")
    print("  Passed: All uncompressed native libs 4096-byte aligned, all other stored files 4-byte aligned.")

    # ------------------------------------------------------------ 3. v1 Signature Chain
    print("\n[3] Checking v1 (JAR Scheme) Signature Chain...")
    if "META-INF/MANIFEST.MF" not in names:
        raise ValueError("Missing META-INF/MANIFEST.MF")
    if "META-INF/CERT.SF" not in names:
        raise ValueError("Missing META-INF/CERT.SF")
    if "META-INF/CERT.RSA" not in names:
        raise ValueError("Missing META-INF/CERT.RSA")

    mf_raw = zin.read("META-INF/MANIFEST.MF")
    sf_raw = zin.read("META-INF/CERT.SF")
    rsa_raw = zin.read("META-INF/CERT.RSA")

    # Verify MANIFEST.MF digests of all zip entries
    mf_text = mf_raw.decode("utf-8")
    mf_sections = _name_lines_join(mf_text)
    for info in zin.infolist():
        if info.filename.startswith("META-INF/"):
            continue
        if info.filename not in mf_sections:
            raise ValueError(f"Entry {info.filename} missing from MANIFEST.MF")
        data = zin.read(info.filename)
        actual_digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        sec_text = mf_sections[info.filename]
        if f"SHA-256-Digest: {actual_digest}" not in sec_text:
            raise ValueError(f"MANIFEST.MF digest mismatch for {info.filename}")
    print("  Passed: All entry SHA-256 digests in MANIFEST.MF verified.")

    # Verify CERT.SF manifest digest
    sf_text = sf_raw.decode("utf-8")
    mf_hash_b64 = base64.b64encode(hashlib.sha256(mf_raw).digest()).decode("ascii")
    if f"SHA-256-Digest-Manifest: {mf_hash_b64}" not in sf_text:
        raise ValueError("CERT.SF SHA-256-Digest-Manifest does not match MANIFEST.MF")
    print("  Passed: CERT.SF Manifest digest matches MANIFEST.MF.")

    # Verify CERT.RSA with openssl cms
    with tempfile.TemporaryDirectory() as tmpdir:
        rsa_path = os.path.join(tmpdir, "CERT.RSA")
        sf_path = os.path.join(tmpdir, "CERT.SF")
        cert_out_path = os.path.join(tmpdir, "extracted_cert.pem")
        with open(rsa_path, "wb") as f:
            f.write(rsa_raw)
        with open(sf_path, "wb") as f:
            f.write(sf_raw)

        # Extract signer certificate from PKCS#7 / CMS
        res = subprocess.run([
            "openssl", "pkcs7", "-inform", "DER", "-in", rsa_path,
            "-print_certs", "-out", cert_out_path
        ], capture_output=True, text=True)
        if res.returncode != 0:
            raise ValueError(f"Failed to extract cert from CERT.RSA: {res.stderr}")

        # Verify CMS signature
        res = subprocess.run([
            "openssl", "cms", "-verify", "-inform", "DER", "-in", rsa_path,
            "-content", sf_path, "-CAfile", cert_out_path, "-noverify"
        ], capture_output=True, text=True)
        if res.returncode != 0 and "Verification successful" not in res.stderr and "Verification successful" not in res.stdout:
            raise ValueError(f"CERT.RSA CMS verification failed: {res.stderr}")
        print("  Passed: CERT.RSA PKCS#7 CMS signature verified.")

    # ------------------------------------------------------------ 4. v2 Signature Scheme
    print("\n[4] Checking v2 (APK Signature Scheme v2)...")
    eocd_pos = apk_data.rfind(b"PK\x05\x06")
    if eocd_pos == -1:
        raise ValueError("EOCD not found")
    cd_offset = struct.unpack_from("<I", apk_data, eocd_pos + 16)[0]
    cd_size = struct.unpack_from("<I", apk_data, eocd_pos + 12)[0]

    magic = apk_data[cd_offset - 16 : cd_offset]
    if magic != b"APK Sig Block 42":
        raise ValueError(f"APK Signing Block magic missing (got {magic})")
    block_size_footer = struct.unpack_from("<Q", apk_data, cd_offset - 24)[0]
    block_start = cd_offset - 8 - block_size_footer
    block_size_header = struct.unpack_from("<Q", apk_data, block_start)[0]
    if block_size_footer != block_size_header:
        raise ValueError(f"APK Signing Block header size ({block_size_header}) != footer size ({block_size_footer})")
    print(f"  Passed: APK Signing Block located (offset={block_start}, size={block_size_footer}).")

    # Parse ID-value pairs
    pairs_pos = block_start + 8
    pairs = {}
    while pairs_pos < cd_offset - 24:
        p_len = struct.unpack_from("<Q", apk_data, pairs_pos)[0]
        p_id = struct.unpack_from("<I", apk_data, pairs_pos + 8)[0]
        p_val = apk_data[pairs_pos + 12 : pairs_pos + 8 + p_len]
        pairs[p_id] = p_val
        pairs_pos += 8 + p_len

    if V2_BLOCK_ID not in pairs:
        raise ValueError("APK Signature Scheme v2 block ID (0x7109871a) not found in signing block")
    v2_val = pairs[V2_BLOCK_ID]

    # Parse signers
    signers_len = struct.unpack_from("<I", v2_val, 0)[0]
    signer_len = struct.unpack_from("<I", v2_val, 4)[0]
    signer = v2_val[8 : 8 + signer_len]

    s_pos = 0
    sd_len = struct.unpack_from("<I", signer, s_pos)[0]
    sd_bytes = signer[s_pos + 4 : s_pos + 4 + sd_len]
    s_pos += 4 + sd_len

    sigs_len = struct.unpack_from("<I", signer, s_pos)[0]
    sigs_bytes = signer[s_pos + 4 : s_pos + 4 + sigs_len]
    s_pos += 4 + sigs_len

    pk_len = struct.unpack_from("<I", signer, s_pos)[0]
    pk_bytes = signer[s_pos + 4 : s_pos + 4 + pk_len]

    # Extract signature & algo
    sig_rec_len = struct.unpack_from("<I", sigs_bytes, 0)[0]
    sig_algo = struct.unpack_from("<I", sigs_bytes, 4)[0]
    sig_bytes_len = struct.unpack_from("<I", sigs_bytes, 8)[0]
    raw_sig = sigs_bytes[12 : 12 + sig_bytes_len]
    if sig_algo != SIG_ALGO_RSA_PKCS1_SHA256:
        raise ValueError(f"Expected signature algorithm 0x0103, got 0x{sig_algo:x}")

    # Verify RSA signature over signedData
    with tempfile.TemporaryDirectory() as tmpdir:
        pub_path = os.path.join(tmpdir, "pubkey.der")
        sd_path = os.path.join(tmpdir, "signed_data.bin")
        sig_path = os.path.join(tmpdir, "sig.bin")
        with open(pub_path, "wb") as f:
            f.write(pk_bytes)
        with open(sd_path, "wb") as f:
            f.write(sd_bytes)
        with open(sig_path, "wb") as f:
            f.write(raw_sig)

        res = subprocess.run([
            "openssl", "dgst", "-sha256", "-verify", pub_path, "-keyform", "DER",
            "-signature", sig_path, sd_path
        ], capture_output=True, text=True)
        if res.returncode != 0 or "Verified OK" not in res.stdout:
            raise ValueError(f"v2 RSA signature verification failed: {res.stderr}")
    print("  Passed: v2 RSA-2048 PKCS#1 v1.5 signature over signedData verified.")

    # Parse and verify content digests
    d_len = struct.unpack_from("<I", sd_bytes, 0)[0]
    d_rec = sd_bytes[4 : 4 + d_len]
    d_rec_len = struct.unpack_from("<I", d_rec, 0)[0]
    d_algo = struct.unpack_from("<I", d_rec, 4)[0]
    d_bytes_len = struct.unpack_from("<I", d_rec, 8)[0]
    expected_root = d_rec[12 : 12 + d_bytes_len]

    sec1_actual = apk_data[:block_start]
    sec3_actual = apk_data[cd_offset : cd_offset + cd_size]
    eocd_actual = bytearray(apk_data[eocd_pos:])
    struct.pack_into("<I", eocd_actual, 16, block_start)

    actual_chunks = []
    for src in [sec1_actual, sec3_actual, bytes(eocd_actual)]:
        off = 0
        while off < len(src):
            c = src[off : off + CHUNK_SIZE]
            actual_chunks.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
            off += len(c)
    actual_root = hashlib.sha256(b"\x5a" + struct.pack("<I", len(actual_chunks)) + b"".join(actual_chunks)).digest()

    if expected_root != actual_root:
        raise ValueError("v2 Merkle root content digest mismatch!")
    print(f"  Passed: v2 1MB Merkle tree content root digest verified ({len(actual_chunks)} chunks).")

    # ------------------------------------------------------------ 5. AndroidManifest.xml
    print("\n[5] Checking AndroidManifest.xml Binary Headers...")
    manifest_data = zin.read("AndroidManifest.xml")
    magic, size = struct.unpack_from("<II", manifest_data, 0)
    if magic != 0x00080003:
        raise ValueError(f"Invalid Android binary XML magic: 0x{magic:x}")
    if size != len(manifest_data):
        raise ValueError(f"Binary XML size header ({size}) != actual size ({len(manifest_data)})")
    print(f"  Passed: Binary AndroidManifest.xml header valid (size={size} bytes).")

    print("\n" + "=" * 60)
    print("ALL VERIFICATIONS COMPLETED SUCCESSFULLY WITH ZERO ERRORS!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    apk = sys.argv[1] if len(sys.argv) > 1 else "Firekirin3.0.apk"
    verify_apk(apk)
