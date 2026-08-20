from __future__ import annotations

import mimetypes
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# =============================================================================
# Best-effort encrypted/password-protected file detection.
#
# HONESTY NOTE (matches the project brief explicitly): this is NOT a
# universal decryptor-detector. It reliably detects a handful of common,
# well-documented cases and reports `encrypted=None` (unknown) for
# everything else, rather than guessing. Never trust `encrypted is False`
# as proof a file is scannable, and never trust `encrypted is None` as
# proof it's safe - `unknown_encryption` gets its own configurable policy
# in encrypted_file_policies precisely because "we don't know" is a real,
# distinct outcome, not an error.
# =============================================================================

_OOXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
_LEGACY_OFFICE_EXTENSIONS = {".doc", ".xls", ".ppt"}
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}

_CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # legacy OLE / MS Office "compound file"
_PK_MAGIC = b"PK\x03\x04"
_PK_EMPTY_MAGIC = b"PK\x05\x06"
_RAR4_MAGIC = b"Rar!\x1a\x07\x00"
_RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
_SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


@dataclass(frozen=True)
class EncryptionDetection:
    encrypted: Optional[bool]  # True / False / None (unknown)
    encryption_type: Optional[str]
    category: str  # matches an encrypted_file_policies.category row


def detect_encryption(file_path: str, filename: str) -> EncryptionDetection:
    ext = Path(filename).suffix.lower()

    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
    except OSError:
        return EncryptionDetection(None, None, "unknown_encryption")

    if header.startswith(b"%PDF"):
        return _detect_pdf(file_path)

    if header.startswith(_PK_MAGIC) or header.startswith(_PK_EMPTY_MAGIC):
        # A real ZIP (or OOXML Office doc, which IS a zip) - can reliably
        # tell via the stdlib zipfile module whether any entry needs a
        # password.
        return _detect_zip(file_path, ext)

    if header.startswith(_CFBF_MAGIC):
        if ext in _OOXML_EXTENSIONS:
            # A MODERN Office extension (.docx etc) stored as a legacy
            # OLE compound file instead of the expected zip/OOXML
            # structure is the well-documented signature of MS Office's
            # own encryption wrapper (EncryptedPackage/EncryptionInfo
            # streams). Reliable positive signal.
            return EncryptionDetection(True, "office_encrypted", "office_encrypted")
        if ext in _LEGACY_OFFICE_EXTENSIONS:
            # Legacy .doc/.xls/.ppt are ALWAYS compound files whether or
            # not they're encrypted - this magic byte alone can't tell
            # the difference without parsing the compound file's stream
            # directory for an "EncryptionInfo"/"0x13" workbook flag,
            # which this project does not implement. Honestly unknown.
            return EncryptionDetection(None, "ole_compound_file", "unknown_encryption")
        return EncryptionDetection(None, "ole_compound_file", "unknown_encryption")

    if header.startswith(_RAR4_MAGIC) or header.startswith(_RAR5_MAGIC):
        # RAR password-protection is a flag bit inside the archive/file
        # headers (format differs between RAR4 and RAR5) - not reliably
        # readable without a real RAR parser, which this project does not
        # implement. Report the container type but not the encryption state.
        return EncryptionDetection(None, "rar_archive", "unknown_encryption")

    if header.startswith(_SEVENZIP_MAGIC):
        return EncryptionDetection(None, "7z_archive", "unknown_encryption")

    if ext in _ARCHIVE_EXTENSIONS:
        # Extension claims an archive type but the magic bytes didn't
        # match anything recognized - could be corrupt, could be a
        # renamed file. Still worth flagging as unknown rather than
        # silently treating it as "definitely not encrypted".
        return EncryptionDetection(None, None, "unknown_encryption")

    return EncryptionDetection(False, None, "default")


def _detect_zip(file_path: str, ext: str) -> EncryptionDetection:
    category = "office_encrypted" if ext in _OOXML_EXTENSIONS else "archive_password_protected"
    try:
        with zipfile.ZipFile(file_path) as zf:
            bad_entry = zf.testzip()
            if bad_entry is not None:
                # testzip() returns the first entry that fails its CRC
                # check WITHOUT needing a password for standard ZipCrypto
                # encryption's entries, but for AES-encrypted zips (WinZip/
                # 7-Zip AES, common for password-protected archives) entries
                # often raise RuntimeError instead - handled below.
                return EncryptionDetection(True, "zip_encrypted", category)
            return EncryptionDetection(False, None, category)
    except RuntimeError as exc:
        # zipfile raises RuntimeError with a message like "File ... is
        # encrypted, password required for extraction" - the standard,
        # reliable signal for a password-protected ZIP.
        if "password" in str(exc).lower() or "encrypt" in str(exc).lower():
            return EncryptionDetection(True, "zip_encrypted", category)
        return EncryptionDetection(None, "zip_archive", category)
    except zipfile.BadZipFile:
        return EncryptionDetection(None, None, "unknown_encryption")


def _detect_pdf(file_path: str) -> EncryptionDetection:
    try:
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
    except ImportError:
        return EncryptionDetection(None, "pdf", "unknown_encryption")

    try:
        reader = PdfReader(file_path)
        return EncryptionDetection(bool(reader.is_encrypted), "pdf_encrypted" if reader.is_encrypted else None, "pdf_encrypted")
    except PdfReadError:
        # A malformed/corrupt PDF isn't necessarily encrypted - just
        # unparseable. Report unknown rather than guessing either way.
        return EncryptionDetection(None, "pdf", "unknown_encryption")
    except Exception:  # noqa: BLE001 - pypdf can raise various parser errors we don't want to crash a scan over
        return EncryptionDetection(None, "pdf", "unknown_encryption")


def detect_mime_type(file_path: str, filename: str) -> str:
    """
    Lightweight MIME detection: a small magic-byte table for the most
    common binary types, falling back to extension-based guessing
    (stdlib `mimetypes`). Not a replacement for libmagic - deliberately
    avoids that system dependency; good enough for display/policy
    purposes in this project, not claimed to be authoritative.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except OSError:
        header = b""

    magic_table = (
        (b"%PDF", "application/pdf"),
        (_PK_MAGIC, "application/zip"),
        (_CFBF_MAGIC, "application/x-ole-storage"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (_RAR4_MAGIC, "application/vnd.rar"),
        (_RAR5_MAGIC, "application/vnd.rar"),
        (_SEVENZIP_MAGIC, "application/x-7z-compressed"),
    )
    for magic, mime in magic_table:
        if header.startswith(magic):
            return mime

    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"
