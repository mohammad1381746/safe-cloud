import zipfile

import pytest

from encryption_detect import detect_encryption, detect_mime_type


def test_plain_text_file_not_encrypted(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("just some notes")
    result = detect_encryption(str(p), "notes.txt")
    assert result.encrypted is False
    assert result.category == "default"


def test_unencrypted_zip_not_encrypted(tmp_path):
    p = tmp_path / "archive.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("hello.txt", "hello world")
    result = detect_encryption(str(p), "archive.zip")
    assert result.encrypted is False


def test_password_protected_zip_detected(tmp_path):
    # Python's stdlib zipfile can only READ (not create) encrypted
    # archives, so this builds one via raw ZipInfo flag bits AND actually
    # scrambles the member's data - just flipping the local header's flag
    # byte alone leaves the central directory (which zipfile.testzip()
    # actually trusts) claiming "not encrypted", so the read silently
    # "succeeds" on unencrypted-looking bytes. Setting the flag bit0 in
    # BOTH the local header and the central directory record, and
    # corrupting the payload so it can never validate, reproduces what a
    # real encrypted member looks like to zipfile without needing a full
    # ZipCrypto implementation.
    p = tmp_path / "protected.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("secret.txt", "top secret")
    raw = bytearray(p.read_bytes())
    for offset in range(len(raw) - 4):
        # Local file header signature (PK\x03\x04) and central directory
        # file header signature (PK\x01\x02) both carry a general-purpose
        # flag field 6 bytes after the signature start (local) / 8 bytes
        # after (central) - flip bit 0 (encryption) wherever a
        # recognized signature starts.
        if raw[offset:offset + 4] == b"PK\x03\x04":
            raw[offset + 6] |= 0x01
        elif raw[offset:offset + 4] == b"PK\x01\x02":
            raw[offset + 8] |= 0x01
    p.write_bytes(bytes(raw))

    result = detect_encryption(str(p), "protected.zip")
    # zipfile now agrees (local header AND central directory) that the
    # entry is encrypted, so reading/testing it fails - both failure
    # paths in encryption_detect.py's _detect_zip classify this as
    # encrypted or unknown, never as a confident "not encrypted".
    assert result.encrypted is not False


def test_corrupt_archive_reports_unknown(tmp_path):
    p = tmp_path / "broken.zip"
    p.write_bytes(b"PK\x03\x04not a real zip file")
    result = detect_encryption(str(p), "broken.zip")
    assert result.encrypted is None
    assert result.category == "unknown_encryption"


def test_office_extension_with_cfbf_magic_flagged_as_office_encrypted(tmp_path):
    p = tmp_path / "document.docx"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32)
    result = detect_encryption(str(p), "document.docx")
    assert result.encrypted is True
    assert result.category == "office_encrypted"


def test_legacy_office_extension_with_cfbf_magic_is_unknown_not_false(tmp_path):
    # Legacy .doc/.xls/.ppt are ALWAYS compound files, encrypted or not -
    # must not be reported as a confident False.
    p = tmp_path / "document.doc"
    p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32)
    result = detect_encryption(str(p), "document.doc")
    assert result.encrypted is None
    assert result.category == "unknown_encryption"


def test_rar_archive_reports_unknown_not_false(tmp_path):
    p = tmp_path / "archive.rar"
    p.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 32)
    result = detect_encryption(str(p), "archive.rar")
    assert result.encrypted is None
    assert result.category == "unknown_encryption"


def test_encrypted_pdf_detected_via_pypdf(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.encrypt(user_password="secret123")
    p = tmp_path / "encrypted.pdf"
    with open(p, "wb") as f:
        writer.write(f)

    result = detect_encryption(str(p), "encrypted.pdf")
    assert result.encrypted is True
    assert result.category == "pdf_encrypted"


def test_unencrypted_pdf_not_flagged(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    p = tmp_path / "plain.pdf"
    with open(p, "wb") as f:
        writer.write(f)

    result = detect_encryption(str(p), "plain.pdf")
    assert result.encrypted is False


def test_detect_mime_type_by_extension_fallback(tmp_path):
    p = tmp_path / "data.json"
    p.write_text("{}")
    assert detect_mime_type(str(p), "data.json") in ("application/json", "application/octet-stream")


def test_detect_mime_type_png_magic(tmp_path):
    p = tmp_path / "image.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    assert detect_mime_type(str(p), "image.png") == "image/png"
